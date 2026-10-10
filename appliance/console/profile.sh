# Only a locally authenticated culvert session on the boot console gets a menu.
# SSH, serial consoles, other virtual terminals and noninteractive commands retain
# their normal behavior. This file must be root-owned, not writable by culvert.
case $- in
  *i*)
    if [ "$(id -un)" = culvert ] && [ "$(tty 2>/dev/null)" = /dev/tty1 ]; then
      /opt/culvert-appliance/bin/culvert-console --admin
      exit
    fi
    ;;
esac
