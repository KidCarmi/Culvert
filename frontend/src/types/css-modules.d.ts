// CSS Modules type surface. Property access yields string | undefined under
// noUncheckedIndexedAccess — className accepts undefined, so unknown class
// names degrade to "no class" instead of lying about their existence.
declare module "*.module.css" {
  const classes: Record<string, string>;
  export default classes;
}
