/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Generic dictionary type used by the ACL internals.
 *
 * */

/**
 *  An interface that defines dictionay type
 *  @interface
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export interface IDictionary<T> {
    [key: string]: T;
}
