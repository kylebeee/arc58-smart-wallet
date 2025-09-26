import { Contract, arc4, assert, itxn, abimethod, GlobalState, bytes, Application } from "@algorandfoundation/algorand-typescript";
import { methodSelector } from "@algorandfoundation/algorand-typescript/arc4";
import { sha256 } from "@algorandfoundation/algorand-typescript/op";

export class RecoveryPlugin extends Contract {

  creator = GlobalState<arc4.UintN64>({ key: 'creator' })

  hash = GlobalState<bytes>({ key: 'hash' })

  @abimethod({ onCreate: 'require' })
  createApplication(creator: arc4.UintN64, hash: bytes): void {
    this.creator.value = creator;
    this.hash.value = hash;
  }

  recover(sender: arc4.UintN64, prehash: bytes, newAdmin: arc4.Address): void {

    assert(this.creator.value === sender, 'sender mismatch');
    assert(sha256(sha256(prehash)) === this.hash.value, 'prehash mismatch');

    itxn.applicationCall({
      appId: this.creator.value.native,
      appArgs: [
        methodSelector('arc58_pluginChangeAdmin(address)void'),
        newAdmin,
      ],
      fee: 0
    }).submit();

    const creatorAddress = Application(this.creator.value.native).address

    itxn.payment({
      sender: creatorAddress,
      receiver: creatorAddress,
      amount: 0,
      fee: 0,
      rekeyTo: creatorAddress
    }).submit();
  }
}
