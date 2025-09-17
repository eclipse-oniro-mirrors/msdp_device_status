/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import inputDeviceCooperate from '@ohos.multimodalInput.inputDeviceCooperate';
import { BusinessError, AsyncCallback} from '@ohos.base';

const Tag:String = "inputDeviceCooperate"

const ERR_INVALID_PARAM = 1;
const  OVERTIME_QUERY: long = 1000;
const   WAIT_OPER: long = 10000;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

//---
function test_enable_promise() {
   let fun_name: string = 'test_enable_promise';
   console.log(Tag, `into func ${fun_name}`);
    try {
        inputDeviceCooperate.enable(true).then(() => {
            console.log(Tag, `promise ${fun_name} return`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_enable_callback() {
   let fun_name: string = 'test_enable_callback';
   console.log(Tag, `into func ${fun_name}`);
   let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
        console.log(Tag,  `callback ${fun_name} on success`);
    };
    try {
        inputDeviceCooperate.enable(true, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_stop_promise() {
	let fun_name: string = 'test_stop_promise';
    console.log(Tag, `into func ${fun_name}`);
	try {
        inputDeviceCooperate.stop().then(() => {
            console.log(Tag,  `callback ${fun_name} on success`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_stop_callback() {
	let fun_name: string = 'test_stop_callback';
    console.log(Tag, `into func ${fun_name}`);
    let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
        console.log(Tag,  `callback ${fun_name} on success`);
    };
	try {
        inputDeviceCooperate.stop(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}

function test_getstate_callback() {
    let fun_name: string = 'test_getstate_callback';
    console.log(Tag, `into func ${fun_name}`);
    let fnCallBack = (err: BusinessError<void>|null, info: inputDeviceCooperate.TraversalSwitchStatus|undefined) => {
        console.log(Tag,  `callback ${fun_name} on success, info:${info}`);
    };
	try {
        let deviceDescriptor = "descriptor";
         inputDeviceCooperate.getState(deviceDescriptor, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag + `end func ${fun_name}`);
}

function test_getstate_promise() {
    let fun_name: string = 'test_getstate_promise';
    console.log(Tag, `into func ${fun_name}`);
	try {
        let deviceDescriptor = "descriptor";
         inputDeviceCooperate.getState(deviceDescriptor).then((data: inputDeviceCooperate.TraversalSwitchStatus) => {
            console.log(Tag, `promise ${fun_name} return`);
        } );
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag + `end func ${fun_name}`);
}

function test_start_callback() {
    let fun_name: string = 'test_start_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let sinkDeviceDescriptor = "descriptor";
        let srcInputDeviceId: int = 0;
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag,  `callback ${fun_name} on success`);
        };
        inputDeviceCooperate.start(sinkDeviceDescriptor, srcInputDeviceId, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error: ${err}` );
    }
     console.log(Tag, `${fun_name} end`);
}


function test_start_promise() {
    let fun_name: string = 'test_start_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let sinkDeviceDescriptor = "descriptor";
        let srcInputDeviceId: int = 0;
        let fnCallBack = () => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDeviceCooperate.start(sinkDeviceDescriptor, srcInputDeviceId).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:${err}`);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_on_off_change() {
    let fun_name: string = 'test_on_off_change';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: inputDeviceCooperate.CooperationCallbackData | undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDeviceCooperate.on('cooperation', fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        inputDeviceCooperate.off('cooperation', fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);

    console.println(Tag + ` out main`);
}