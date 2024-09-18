import { Contract } from '@algorandfoundation/tealscript';
import { AkitaDomain, RekeyNote } from './constants';
import * as err from './errors';

type PluginsKey = {
  /** The application containing plugin logic */
  application: AppID;
  /** The address that is allowed to initiate a rekey to the plugin */
  allowedCaller: Address;
};

type PluginInfo = {
  /** The last round at which this plugin can be called */
  lastValidRound: uint64;
  /** The number of rounds that must pass before the plugin can be called again */
  cooldown: uint64;
  /** The last round the plugin was called */
  lastCalled: uint64;
  /** Whether the plugin has permissions to change the admin account */
  adminPrivileges: uint8;
};

export class AbstractedAccount extends Contract {
  /** Target AVM 10 */
  programVersion = 10;

  version = GlobalStateKey<string>({ key: 'v' });

  factoryApp = GlobalStateKey<AppID>({ key: 'f' })

  /** The admin of the abstracted account. This address can add plugins and initiate rekeys */
  admin = GlobalStateKey<Address>({ key: 'a' });

  /** The address this app controls */
  controlledAddress = GlobalStateKey<Address>({ key: 'c' });

  /** The app that can revoke plugins */
  revocationApp = GlobalStateKey<AppID>({ key: 'r' });

  /**
   * Plugins that add functionality to the controlledAddress and the account that has permission to use it.
   */
  plugins = BoxMap<PluginsKey, PluginInfo>();

  /**
   * Passkeys on the account and their corresponding domain names
   * address-passkey-name : domain
   * IMPORTANT: a passkey attached to the akita domain is a co-admin passkey
   * we explicitly have this feature so that the wallet can be used on multiple incompatible devices
   * we track this onchain so we can assist with 'sign-in from another device' functionality
   * as well as potential future uses like DAO based domain revocation
   * if they max the name out at 32 its 2_500 + (400 * (33 + ?)) = min 27_200 given the shortest domain length is like 4 characters
   */
  passkeys = BoxMap<Address, bytes>();

  /**
   * Plugins that have been given a name for discoverability
   */
  namedPlugins = BoxMap<bytes, PluginsKey>({ prefix: 'n' });

  /**
   * Ensure that by the end of the group the abstracted account has control of its address
   */
  private verifyRekeyToAbstractedAccount(): void {
    let rekeyedBack = false;

    for (let i = this.txn.groupIndex; i < this.txnGroup.length; i += 1) {
      const txn = this.txnGroup[i];

      // The transaction is an explicit rekey back
      if (txn.sender === this.controlledAddress.value && txn.rekeyTo === this.controlledAddress.value) {
        rekeyedBack = true;
        break;
      }

      // The transaction is an application call to this app's arc58_verifyAuthAddr method
      if (
        txn.typeEnum === TransactionType.ApplicationCall &&
        txn.applicationID === this.app &&
        txn.numAppArgs === 1 &&
        txn.applicationArgs[0] === method('arc58_verifyAuthAddr()void')
      ) {
        rekeyedBack = true;
        break;
      }
    }

    assert(rekeyedBack);
  }

  /**
   * What the value of this.address.value.authAddr should be when this.controlledAddress
   * is able to be controlled by this app. It will either be this.app.address or zeroAddress
   * 
   * @returns the auth address that the contract should be rekeyed back to at the end of a flash rekey
   */
  private getAuthAddr(): Address {
    return this.controlledAddress.value === this.app.address
      ? Address.zeroAddress : this.app.address;
  }

  /**
   * 
   * @returns whether or not the caller is an admin on the wallet
   */
  private isAdmin(): boolean {
    return (
      this.txn.sender === this.admin.value ||
      this.passkeys(this.txn.sender).exists &&
      this.passkeys(this.txn.sender).value == AkitaDomain
    );
  }

  /**
   * 
   * @returns whether the caller is the revocation app address
   */
  private canRevoke(): boolean {
    return this.txn.sender === this.revocationApp.value.address
  }

  /**
   * 
   * @param app the plugin App ID
   * @param caller the address calling the plugin
   * @returns whether the plugin call should be allowed
   */
  private pluginCallAllowed(app: AppID, caller: Address): boolean {
    const key: PluginsKey = { application: app, allowedCaller: caller };

    return (
      this.plugins(key).exists &&
      this.plugins(key).value.lastValidRound >= globals.round &&
      (globals.round - this.plugins(key).value.lastCalled) >= this.plugins(key).value.cooldown
    );
  }

  /**
   * Create an abstracted account application.
   * This is not part of ARC58 and implementation specific.
   *
   * @param controlledAddress The address of the abstracted account. If zeroAddress, then the address of the contract account will be used
   * @param admin The admin for this app
   */
  createApplication(
    version: string,
    controlledAddress: Address,
    admin: Address,
    revocationApp: AppID
  ): void {
    assert(admin !== controlledAddress, "admin and controlled address cannot be the same");
    assert(globals.callerApplicationID !== AppID.fromUint64(0), "this contract must be deployed from a factory")

    this.version.value = version;
    this.factoryApp.value = globals.callerApplicationID
    this.admin.value = admin;
    this.revocationApp.value = revocationApp;
    this.controlledAddress.value = controlledAddress === Address.zeroAddress ? this.app.address : controlledAddress;
  }

  updateApplication(version: string): void {
    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_UPDATE);
    this.version.value = version;
  }

  /**
   * Changes the revocation app associated with the contract
   * 
   * @param newRevocationApp the new revocation app
   */
  changeRevocationApp(newRevocationApp: AppID): void {
    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_CHANGE_REVOKE);
    this.revocationApp.value = newRevocationApp;
  }

  /**
   * Attempt to change the admin for this app. Some implementations MAY not support this.
   *
   * @param newAdmin The new admin
   */
  arc58_changeAdmin(newAdmin: Address): void {
    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_CHANGE_ADMIN);
    this.admin.value = newAdmin;
  }

  /**
   * Attempt to change the admin via plugin.
   *
   * @param plugin The app calling the plugin
   * @param allowedCaller The address that triggered the plugin
   * @param newAdmin The new admin
   * 
   */
  arc58_pluginChangeAdmin(plugin: AppID, allowedCaller: Address, newAdmin: Address): void {
    verifyTxn(this.txn, { sender: plugin.address });
    assert(
      this.controlledAddress.value.authAddr === plugin.address,
      err.PLUGIN_DOES_NOT_CONTROL_WALLET
    );

    const key: PluginsKey = { application: plugin, allowedCaller: allowedCaller };
    assert(
      this.plugins(key).exists && this.plugins(key).value.adminPrivileges,
      err.PLUGIN_DOES_NOT_HAVE_ADMIN_PRIVILEGES
    );

    this.admin.value = newAdmin;
  }

  /**
   * Verify the abstracted account is rekeyed to this app
   */
  arc58_verifyAuthAddr(): void {
    assert(this.controlledAddress.value.authAddr === this.getAuthAddr());
  }

  /**
   * Rekey the abstracted account to another address. Primarily useful for rekeying to an EOA.
   *
   * @param addr The address to rekey to
   * @param flash Whether or not this should be a flash rekey.
   * If true, the rekey back to the app address must done in the same txn group as this call
   */
  arc58_rekeyTo(addr: Address): void {

    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_REKEY);

    sendPayment({
      sender: this.controlledAddress.value,
      receiver: addr,
      rekeyTo: addr,
      fee: 0,
      note: 'rekeying abstracted account',
    });

    this.verifyRekeyToAbstractedAccount();
  }

  /**
   * Temporarily rekey to an approved plugin app address
   *
   * @param plugin The app to rekey to
   */
  arc58_rekeyToPlugin(plugin: AppID): void {
    const globalAllowed = this.pluginCallAllowed(plugin, Address.zeroAddress);

    if (!globalAllowed)
      assert(
        this.pluginCallAllowed(plugin, this.txn.sender),
        err.SENDER_NOT_ALLOWED_TO_CALL_PLUGIN
      );

    sendPayment({
      sender: this.controlledAddress.value,
      receiver: this.controlledAddress.value,
      rekeyTo: plugin.address,
      note: RekeyNote,
    });

    this.plugins({
      application: plugin,
      allowedCaller: globalAllowed ? Address.zeroAddress : this.txn.sender,
    }).value.lastCalled = globals.round;

    this.verifyRekeyToAbstractedAccount();
  }

  /**
   * Temporarily rekey to a named plugin app address
   *
   * @param name The name of the plugin to rekey to
   */
  arc58_rekeyToNamedPlugin(name: string): void {
    this.arc58_rekeyToPlugin(this.namedPlugins(name).value.application);
  }

  /**
   * Add an app to the list of approved plugins
   *
   * @param app The app to add
   * @param allowedCaller The address of that's allowed to call the app
   * or the global zero address for all addresses
   * @param lastValidRound The round when the permission expires
   * @param cooldown  The number of rounds that must pass before the plugin can be called again
   * @param adminPrivileges Whether the plugin has permissions to change the admin account
   */
  arc58_addPlugin(
    app: AppID,
    allowedCaller: Address,
    lastValidRound: uint64,
    cooldown: uint64,
    adminPrivileges: boolean,
    isPasskey: boolean,
    domain: string,
  ): void {
    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_ADD_PLUGIN);

    const key: PluginsKey = { application: app, allowedCaller: allowedCaller };

    this.plugins(key).value = {
      lastValidRound: lastValidRound,
      cooldown: cooldown,
      lastCalled: 0,
      adminPrivileges: adminPrivileges ? 1 as uint8 : 0 as uint8,
    };

    if (isPasskey) {
      assert(domain.length > 0, err.DOMAIN_MUST_BE_LONGER_THAN_ZERO);
      this.passkeys(allowedCaller).value = domain;
    }
  }

  /**
   * Remove an app from the list of approved plugins
   *
   * @param app The app to remove
   */
  arc58_removePlugin(app: AppID, allowedCaller: Address): void {
    assert(
      this.isAdmin() || this.canRevoke(),
      err.ONLY_ADMIN_OR_REVOCATION_APP_CAN_REMOVE_PLUGIN
    );

    const key: PluginsKey = { application: app, allowedCaller: allowedCaller };
    this.plugins(key).delete();
  }

  /**
   * Add a named plugin
   *
   * @param app The plugin app
   * @param name The plugin name
   * @param allowedCaller The address of that's allowed to call the app
   * or the global zero address for all addresses
   * @param lastValidRound The round when the permission expires
   * @param cooldown  The number of rounds that must pass before the plugin can be called again
   * @param adminPrivileges Whether the plugin has permissions to change the admin account
   */
  arc58_addNamedPlugin(
    name: string,
    app: AppID,
    allowedCaller: Address,
    lastValidRound: uint64,
    cooldown: uint64,
    adminPrivileges: boolean
  ): void {
    assert(this.isAdmin(), err.ONLY_ADMIN_CAN_ADD_PLUGIN);
    assert(!this.namedPlugins(name).exists, err.NAMED_PLUGIN_ALREADY_EXISTS);

    const key: PluginsKey = { application: app, allowedCaller: allowedCaller };
    this.namedPlugins(name).value = key;
    this.plugins(key).value = {
      lastValidRound: lastValidRound,
      cooldown: cooldown,
      lastCalled: 0,
      adminPrivileges: adminPrivileges ? 1 as uint8 : 0 as uint8,
    };
  }

  /**
   * Remove a named plugin
   *
   * @param name The plugin name
   */
  arc58_removeNamedPlugin(name: string): void {
    assert(
      this.isAdmin() || this.canRevoke(),
      err.ONLY_ADMIN_OR_REVOCATION_APP_CAN_REMOVE_PLUGIN
    );

    const app = this.namedPlugins(name).value;
    this.namedPlugins(name).delete();
    this.plugins(app).delete();
  } 
}
