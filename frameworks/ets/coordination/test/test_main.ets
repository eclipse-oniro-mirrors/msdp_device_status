/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import cooperate from '@ohos.cooperate';
import { BusinessError, AsyncCallback} from '@ohos.base';

const Tag:String = "cooperate"

const ERR_INVALID_PARAM = 1;
const  OVERTIME_QUERY: long = 1000;
const  WAIT_OPER: long = 10000;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

//---
function test_prepareCooperate_promise() {
   let fun_name: string = 'test_prepareCooperate_promise';
   console.log(Tag, `into func ${fun_name}`);
    try {
        cooperate.prepareCooperate().then(() => {
            console.log(Tag, `promise ${fun_name} return`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_prepareCooperate_callback() {
   let fun_name: string = 'test_prepareCooperate_callback';
   console.log(Tag, `into func ${fun_name}`);
   let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
        console.log(Tag,  `callback ${fun_name} on success`);
    };
    try {
        cooperate.prepareCooperate(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_unprepareCooperate_promise() {
	let fun_name: string = 'test_unprepareCooperate_promise';
    console.log(Tag, `into func ${fun_name}`);
	try {
        cooperate.unprepareCooperate().then(() => {
            console.log(Tag,  `callback ${fun_name} on success`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_unprepareCooperate_callback() {
	let fun_name: string = 'test_unprepareCooperate_callback';
    console.log(Tag, `into func ${fun_name}`);
    let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
        console.log(Tag,  `callback ${fun_name} on success`);
    };
	try {
        cooperate.unprepareCooperate(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_activateCooperate_promise() {
    let fun_name: string = 'test_activateCooperate_promise';
    console.log(Tag, `into func ${fun_name}`);
	try {
        let targetNetworkId = "testNetworkId";
        let inputDeviceId: int = 1;
        cooperate.activateCooperate(targetNetworkId, inputDeviceId).then(() => {
            console.log(Tag, `promise ${fun_name} return`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag + `end func ${fun_name}`);
}

function test_activateCooperate_callback() {
    let fun_name: string = 'test_activateCooperate_callback';
    console.log(Tag, `into func ${fun_name}`);
    let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
        console.log(Tag,  `callback ${fun_name} on success`);
    };
	try {
        let targetNetworkId = "testNetworkId";
        let inputDeviceId: int = 1;
        cooperate.activateCooperate(targetNetworkId, inputDeviceId, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag + `end func ${fun_name}`);
}

function test_deactivateCooperate_promise() {
    let fun_name: string = 'test_deactivateCooperate_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let isUnchained: boolean = false;
        cooperate.deactivateCooperate(isUnchained).then(() => {
            console.log(Tag, `promise ${fun_name} return`);
        });
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:${err}`);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_deactivateCooperate_callback() {
    let fun_name: string = 'test_deactivateCooperate_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let isUnchained: boolean = false;
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag,  `callback ${fun_name} on success`);
        };
        cooperate.deactivateCooperate(isUnchained, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error: ${err}` );
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getCooperateSwitchState_promise() {
    let fun_name: string = 'test_getCooperateSwitchState_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let networkId = "testNetworkId";
        cooperate.getCooperateSwitchState(networkId).then((data: boolean) => {
            console.log(Tag, `promise ${fun_name} return`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:${err}`);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getCooperateSwitchState_callback() {
    let fun_name: string = 'test_getCooperateSwitchState_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let networkId = "testNetworkId";
        let fnCallBack = (err: BusinessError<void>|null, info: boolean |undefined) => {
            console.log(Tag,  `callback ${fun_name} on success, info: ${info}`);
        };
        cooperate.getCooperateSwitchState(networkId, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error: ${err}` );
    }
     console.log(Tag, `${fun_name} end`);
}

function test_activateCooperateWithOptions_promise() {
    let fun_name: string = 'test_activateCooperateWithOptions_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let targetNetworkId = "testNetworkId";
        let inputDeviceId: int = 1;
        let cooperateOptions : cooperate.CooperateOptions | undefined;
        cooperate.activateCooperateWithOptions(targetNetworkId, inputDeviceId, cooperateOptions).then(() => {
            console.log(Tag, `promise ${fun_name} return`);
        });
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:${err}`);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_cooperateMessage_change() {
    let fun_name: string = 'test_cooperateMessage_change';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: cooperate.CooperateMessage | undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        cooperate.on('cooperateMessage', fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        cooperate.off('cooperateMessage', fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function test_cooperateMouse_change() {
    let fun_name: string = 'test_cooperateMouse_change';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: cooperate.MouseLocation | undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let networkId = "testNetworkId";
        cooperate.on('cooperateMouse', networkId, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        cooperate.off('cooperateMouse', networkId, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    test_prepareCooperate_promise();
    test_prepareCooperate_callback();
    test_unprepareCooperate_promise();
    test_unprepareCooperate_callback();
    test_activateCooperate_promise();
    test_activateCooperate_callback();
    test_deactivateCooperate_promise();
    test_deactivateCooperate_callback();
    test_getCooperateSwitchState_promise();
    test_getCooperateSwitchState_callback();
    test_activateCooperateWithOptions_promise();
    test_cooperateMessage_change();
    test_cooperateMouse_change();
    console.println(Tag + ` out main`);
}