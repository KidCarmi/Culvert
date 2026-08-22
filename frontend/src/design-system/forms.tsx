// Form primitives with the label/help/error contract (FE-2 §7): every control
// is labelled; help and error text are programmatically associated via
// aria-describedby; invalid state sets aria-invalid — never color alone.
import { useId } from "react";
import type {
  InputHTMLAttributes,
  JSX,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { IconAlert } from "./icons";
import styles from "./forms.module.css";

interface FieldChrome {
  label: string;
  required?: boolean;
  help?: string;
  error?: string;
}

interface FieldRenderProps {
  id: string;
  describedBy: string | undefined;
  invalid: boolean;
}

function Field({
  label,
  required,
  help,
  error,
  children,
}: FieldChrome & {
  children: (p: FieldRenderProps) => ReactNode;
}): JSX.Element {
  const id = useId();
  const helpId = `${id}-help`;
  const errId = `${id}-err`;
  const describedBy =
    [help !== undefined ? helpId : "", error !== undefined ? errId : ""]
      .filter((s) => s !== "")
      .join(" ") || undefined;
  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
        {required === true && (
          <span className={styles.required} aria-hidden="true">
            *
          </span>
        )}
      </label>
      {children({ id, describedBy, invalid: error !== undefined })}
      {help !== undefined && (
        <p className={styles.help} id={helpId}>
          {help}
        </p>
      )}
      {error !== undefined && (
        <p className={styles.error} id={errId}>
          <IconAlert size={12} />
          {error}
        </p>
      )}
    </div>
  );
}

type InputProps = FieldChrome &
  Omit<InputHTMLAttributes<HTMLInputElement>, "id">;

export function InputField({
  label,
  required,
  help,
  error,
  ...rest
}: InputProps): JSX.Element {
  const chrome: FieldChrome = { label };
  if (required !== undefined) chrome.required = required;
  if (help !== undefined) chrome.help = help;
  if (error !== undefined) chrome.error = error;
  return (
    <Field {...chrome}>
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          className={styles.input}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          {...rest}
        />
      )}
    </Field>
  );
}

type TextareaProps = FieldChrome &
  Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id">;

export function TextareaField({
  label,
  required,
  help,
  error,
  ...rest
}: TextareaProps): JSX.Element {
  const chrome: FieldChrome = { label };
  if (required !== undefined) chrome.required = required;
  if (help !== undefined) chrome.help = help;
  if (error !== undefined) chrome.error = error;
  return (
    <Field {...chrome}>
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          className={styles.textarea}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          {...rest}
        />
      )}
    </Field>
  );
}

type SelectProps = FieldChrome &
  Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> & { children: ReactNode };

export function SelectField({
  label,
  required,
  help,
  error,
  children,
  ...rest
}: SelectProps): JSX.Element {
  const chrome: FieldChrome = { label };
  if (required !== undefined) chrome.required = required;
  if (help !== undefined) chrome.help = help;
  if (error !== undefined) chrome.error = error;
  return (
    <Field {...chrome}>
      {({ id, describedBy, invalid }) => (
        <select
          id={id}
          className={styles.select}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          {...rest}
        >
          {children}
        </select>
      )}
    </Field>
  );
}

export function Checkbox({
  label,
  ...rest
}: { label: string } & Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "id" | "type"
>): JSX.Element {
  const id = useId();
  return (
    <label className={styles.checkboxRow} htmlFor={id}>
      <input id={id} type="checkbox" className={styles.checkbox} {...rest} />
      {label}
    </label>
  );
}

// Switch: for immediate-effect binary settings (semantically a switch, not a
// form-submitted checkbox).
export function Switch({
  label,
  ...rest
}: { label: string } & Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "id" | "type" | "role"
>): JSX.Element {
  const id = useId();
  return (
    <label className={styles.checkboxRow} htmlFor={id}>
      <input
        id={id}
        type="checkbox"
        role="switch"
        className={styles.switch}
        {...rest}
      />
      {label}
    </label>
  );
}
