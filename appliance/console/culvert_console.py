#!/usr/bin/env python3
"""Appliance console. Public display -> PAM login -> unprivileged admin menu."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from console_status import collect, clean, lines, ENV

HERE = Path(__file__).resolve().parent
BIN = '/opt/culvert-appliance/bin/'


def admin_identity():
    import pwd
    return os.geteuid() != 0 and pwd.getpwuid(os.geteuid()).pw_name == 'culvert'


def screen(window, admin=False):
    import curses
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    window.timeout(500)
    refresh = 0
    last_input = time.monotonic()
    snapshot = None
    diagnostics = False
    while True:
        repaint = False
        if time.monotonic() >= refresh:
            snapshot = collect()
            refresh = time.monotonic() + 5
            repaint = True
        window.erase()
        # Firstboot/kernel messages may also write to the VGA console. Force a
        # repaint so curses does not assume its previous pixels are still there.
        if repaint:
            window.clear()
        body = lines(snapshot)
        if diagnostics:
            body = ['CULVERT DIAGNOSTICS (no credentials)', '',
                    'Reason: ' + snapshot['reason']]
            body += [key + ': ' + clean(value) for key, value in snapshot['firstboot'].items()]
            body += ['', 'Check VM network mapping if no address is shown.',
                     'A failed firstboot may need a corrected appliance image.',
                     'A retry does not repair missing image content.']
        footer = (['', '[1] Network info  [2] Setup access  [3] Diagnostics',
                   '[4] Retry provisioning  [5] Restart/shutdown',
                   '[6] Recovery shell  [Q] Log out'] if admin else
                  ['', '[F2 / 2] Sign in  [F4 / 4] Diagnostics  [R] Refresh',
                   'Key-only account? Use SSH with your imported key.',
                   'Console password can be set from authenticated SSH.'])
        height, width = window.getmaxyx()
        # Keep actions visible on the standard 80x25 VMware VGA console.
        visible = body[:max(0, height - len(footer) - 1)] + footer
        for row, line in enumerate(visible[:max(0, height - 1)]):
            try:
                window.addstr(row, 0, clean(line, max(0, width - 1)))
            except curses.error:
                pass
        window.refresh()
        key = window.getch()
        if key >= 0:
            last_input = time.monotonic()
        elif admin and time.monotonic() - last_input >= 300:
            return 'logout'
        if key in (ord('r'), ord('R'), curses.KEY_RESIZE):
            refresh = 0
        elif (not admin and key in (ord('4'), curses.KEY_F4)) or (admin and key == ord('3')):
            diagnostics = not diagnostics
        elif not admin and key in (ord('2'), curses.KEY_F2):
            return 'login'
        elif admin and key in (ord('q'), ord('Q')):
            return 'logout'
        elif admin and key in map(ord, '12456'):
            return chr(key)


def execute(args):
    # Inherit the terminal for sudo/PAM; never capture or log credential output.
    return subprocess.call(args, env={**ENV, 'TERM': os.environ.get('TERM', 'linux'),
                                     'HOME': str(Path.home())})


def action(choice):
    """Fixed argv only; the public mode never calls this function."""
    if not admin_identity():
        raise PermissionError('Sign in as culvert before using recovery actions.')
    if choice == '1':
        execute([BIN + 'culvert-net', 'show'])
        print('\nGuided network changes with rollback are not included in this slice.')
        print('Use the authenticated recovery shell for the existing culvert-net helper.')
    elif choice == '2':
        print('Setup token is shown only when setup is pending; do not share it.')
        execute(['/usr/bin/sudo', '--', BIN + 'culvert-status'])
    elif choice == '4':
        current = collect()
        if current['firstboot'].get('ActiveState') not in ('failed', 'inactive') or any(
                s['id'] == 'complete' and s['state'] == 'recorded' for s in current['steps']):
            print('Retry refused: provisioning is running, complete, or its status is unknown.')
        elif input('Type RETRY to resume incomplete provisioning: ') == 'RETRY':
            # Recheck after the confirmation; systemd serializes service start jobs.
            current = collect()
            if current['firstboot'].get('ActiveState') in ('failed', 'inactive') and not any(
                    s['id'] == 'complete' and s['state'] == 'recorded' for s in current['steps']):
                if execute(['/usr/bin/sudo', '--', '/usr/bin/systemctl', 'reset-failed',
                            'culvert-firstboot.service']) == 0:
                    execute(['/usr/bin/sudo', '--', '/usr/bin/systemctl', 'start', '--no-block',
                             'culvert-firstboot.service'])
            else:
                print('State changed; no retry dispatched.')
    elif choice == '5':
        confirmation = input('Type REBOOT or POWEROFF (anything else cancels): ')
        if confirmation in ('REBOOT', 'POWEROFF'):
            execute(['/usr/bin/sudo', '--', '/usr/bin/systemctl', confirmation.lower()])
    elif choice == '6':
        print('Authenticated recovery shell. Type exit to return to the menu.')
        execute(['/bin/bash', '--noprofile', '--norc'])
    input('\nPress Enter to return to the menu...')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--login', action='store_true', help='boot console, root getty service only')
    modes.add_argument('--admin', action='store_true', help='authenticated culvert account menu')
    modes.add_argument('--json', action='store_true', help='read-only status; never includes secrets')
    modes.add_argument('--text', action='store_true', help='read-only plain text status')
    args = parser.parse_args()
    if args.json or args.text:
        snapshot = collect()
        print(json.dumps(snapshot) if args.json else '\n'.join(lines(snapshot)))
        return 0
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('interactive modes require a terminal')
    if args.login and (os.geteuid() != 0 or os.ttyname(0) != '/dev/tty1'):
        parser.error('--login requires root on /dev/tty1')
    if args.admin and not admin_identity():
        parser.error('--admin requires an authenticated culvert user')
    import curses
    while True:
        try:
            choice = curses.wrapper(screen, args.admin)
            if choice == 'logout':
                return 0
            sys.stdout.write('\033[2J\033[H')
            sys.stdout.flush()
            if choice == 'login':
                # No -f, no password handling, no auto-login. PAM owns authentication.
                execute(['/bin/login', 'culvert'])
            else:
                action(choice)
        except (KeyboardInterrupt, EOFError):
            if args.admin:
                return 0
        except (OSError, curses.error):
            # Public UI failure falls back to normal login, never an unauthenticated shell.
            if args.login:
                os.execve('/bin/login', ['/bin/login', 'culvert'],
                          {**ENV, 'TERM': 'linux'})
            print('Console unavailable. Sign in through SSH for recovery.', file=sys.stderr)
            return 1


if __name__ == '__main__':
    sys.exit(main())
