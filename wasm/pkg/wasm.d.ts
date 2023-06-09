/* tslint:disable */
/* eslint-disable */
/**
*/
export function init(): void;
/**
*/
export class Account {
  free(): void;
/**
* @param {string} address
* @returns {Account}
*/
  static _new(address: string): Account;
/**
* @param {string} account
* @returns {Account}
*/
  static fromString(account: string): Account;
/**
* @returns {string}
*/
  toString(): string;
/**
* @param {number | undefined} new_index
*/
  updateIndex(new_index?: number): void;
/**
* @param {string} account
* @param {number} new_index
* @returns {string}
*/
  static updateIndexFromString(account: string, new_index: number): string;
/**
* @returns {any}
*/
  balance(): any;
/**
* @returns {string}
*/
  blinding(): string;
/**
* @returns {number | undefined}
*/
  index(): number | undefined;
}
/**
*/
export class Protocol {
  free(): void;
/**
* @param {Uint8Array} pk
* @param {Uint8Array} vk
* @param {string} account
* @param {any} tree_notes
* @param {any} diffs
* @returns {any}
*/
  static deposit_withdraw_with_check(pk: Uint8Array, vk: Uint8Array, account: string, tree_notes: any, diffs: any): any;
/**
* @param {Uint8Array} pk
* @param {string} account
* @param {any} tree_notes
* @param {any} diffs
* @returns {any}
*/
  static deposit_withdraw(pk: Uint8Array, account: string, tree_notes: any, diffs: any): any;
/**
* @param {Uint8Array} pk
* @param {string} account
* @param {any} tree_notes
* @param {any} diffs
* @param {any} swap_argument
* @param {bigint | undefined} timeout
* @returns {any}
*/
  static swap(pk: Uint8Array, account: string, tree_notes: any, diffs: any, swap_argument: any, timeout?: bigint): any;
}
/**
*/
export class SparseMerkleTree {
  free(): void;
/**
*/
  constructor();
/**
* @returns {string}
*/
  root(): string;
/**
* @param {any} leaf_list
*/
  insert_batch(leaf_list: any): void;
/**
*/
  latest_index: number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_account_free: (a: number) => void;
  readonly account__new: (a: number, b: number) => number;
  readonly account_fromString: (a: number, b: number) => number;
  readonly account_toString: (a: number, b: number) => void;
  readonly account_updateIndex: (a: number, b: number, c: number) => void;
  readonly account_updateIndexFromString: (a: number, b: number, c: number, d: number) => void;
  readonly account_balance: (a: number) => number;
  readonly account_blinding: (a: number, b: number) => void;
  readonly account_index: (a: number, b: number) => void;
  readonly protocol_deposit_withdraw_with_check: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly protocol_deposit_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly protocol_swap: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
  readonly __wbg_protocol_free: (a: number) => void;
  readonly init: () => void;
  readonly __wbg_sparsemerkletree_free: (a: number) => void;
  readonly __wbg_get_sparsemerkletree_latest_index: (a: number) => number;
  readonly __wbg_set_sparsemerkletree_latest_index: (a: number, b: number) => void;
  readonly sparsemerkletree_new: () => number;
  readonly sparsemerkletree_root: (a: number, b: number) => void;
  readonly sparsemerkletree_insert_batch: (a: number, b: number) => void;
  readonly interface_version_8: () => void;
  readonly allocate: (a: number) => number;
  readonly deallocate: (a: number) => void;
  readonly requires_stargate: () => void;
  readonly requires_iterator: () => void;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
