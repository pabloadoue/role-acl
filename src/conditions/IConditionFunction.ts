/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Interface for condition evaluators used by the condition runtime.
 *
 * */
/**
 *  Condition function interface
 *  @interface
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */

export interface IConditionFunction {
    evaluate(args?: any, context?: any): boolean | Promise<boolean>;
}
