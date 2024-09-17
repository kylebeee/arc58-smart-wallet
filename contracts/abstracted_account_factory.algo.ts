import { Contract } from "@algorandfoundation/tealscript";
import { AbstractedAccount } from "./abstracted_account.algo";

export class AbstractedAccountFactory extends Contract {

    abstractedAccountVersion = GlobalStateKey<string>();
    revocationAppID = GlobalStateKey<AppID>();

    createApplication(version: string, revocationAppID: AppID): void {
        this.abstractedAccountVersion.value = version;
        this.revocationAppID.value = revocationAppID;
    }

    updateApplication(): void {
        assert(this.txn.sender === this.app.creator)
    }

    mint(controlledAddress: Address, admin: Address) {
        sendMethodCall<[string, Address, Address, AppID], void>({
            name: 'createApplication',
            applicationArgs: [
                this.abstractedAccountVersion.value,
                controlledAddress,
                admin,
                rawBytes(this.revocationAppID.value),
            ],
            approvalProgram: AbstractedAccount.approvalProgram(),
            clearStateProgram: AbstractedAccount.clearProgram(),
            globalNumUint: AbstractedAccount.schema.global.numUint,
            globalNumByteSlice: AbstractedAccount.schema.global.numByteSlice,
            fee: 0,
        });
    }
}