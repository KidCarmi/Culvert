// React act() environment flag for the FE-1A mount test — declared globally so
// the assignment needs no type assertion (assertions are lint-banned).
declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}
export {};
