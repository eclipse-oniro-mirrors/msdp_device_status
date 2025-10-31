/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import metadataBinding from '@ohos.multimodalAwareness.metadataBinding';
import { BusinessError, AsyncCallback} from '@ohos.base';
import image from '@ohos.multimedia.image';
import rpc from "@ohos.rpc";
 
const Tag:String = "metadataBinding"
 
function test_onMetadata() {
    let fun_name: string = 'test_onMetadata';
    console.log(Tag, `into func ${fun_name}`);
 
    let bundleName: string = '';
    try {
        metadataBinding.on('operationSubmitMetadata', bundleName, (event: int) =>{
            if (event == 1) {
                console.info("The screenshot request is intercepted and the app link is obtained");
            }
        });
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}
 
function test_offMetadata() {
    let fun_name: string = 'test_offMetadata';
    console.log(Tag, `into func ${fun_name}`);
 
    let bundleName: string = '';
    try {
        metadataBinding.off('operationSubmitMetadata', bundleName, (event: int)=>{});
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}
 
function test_notifyMetadataBindingEvent() {
    let fun_name: string = 'test_notifyMetadataBindingEvent';
    console.log(Tag, `into func ${fun_name}`);
    let metadata:string = '';
    metadataBinding.notifyMetadataBindingEvent(metadata).catch((err)=>{
        console.error(Tag, `${fun_name} catch ${err}`);
    });
    console.log(Tag, `end func ${fun_name}`);
}
 
function test_submitMetadata() {
    let fun_name: string = 'test_submitMetadata';
    console.log(Tag, `into func ${fun_name}`);
 
    let metadata: string = "";
    try {
        metadataBinding.submitMetadata(metadata);
    } catch (err) {
        console.error(Tag, `${fun_name} catch ${err}`);
    }
    console.log(Tag, `end func ${fun_name}`);
}
 
function test_encodeImage() {
    let fun_name: string = 'test_encodeImage';
    console.log(Tag, `into func ${fun_name}`);
    let captureImage: image.PixelMap;
    let metadata: string = "";
    let parcel:rpc.MessageSequence = new rpc.MessageSequence();
    let srcImage : image.PixelMap = image.createPixelMapFromParcel(parcel);
    metadataBinding.encodeImage(srcImage, metadata).then((pixelMap: image.PixelMap) =>{
        console.log(Tag, `enter then ${fun_name}`);
        captureImage = pixelMap;
    }).catch((err)=>{
        console.error(Tag, `${fun_name} catch ${err}`);
    });
    console.log(Tag, `end func ${fun_name}`);
}
 
function test_decodeImage() {
    let fun_name: string = 'test_decodeImage';
    console.log(Tag, `into func ${fun_name}`);
 
    let parcel:rpc.MessageSequence = new rpc.MessageSequence();
    let encodeImage : image.PixelMap = image.createPixelMapFromParcel(parcel);
    let captureMetadata: string = "";
    metadataBinding.decodeImage(encodeImage).then((metadata: string) =>{
        console.log(Tag, `enter then ${fun_name}`);
        captureMetadata = metadata;
    }).catch((err)=>{
        console.error(Tag, `${fun_name} catch ${err}`);
    }); 
    console.log(Tag, `end func ${fun_name}`);
}
 
function main() {
    console.log(Tag, ` into main`);
    test_onMetadata();
    test_offMetadata();
    test_notifyMetadataBindingEvent();
    test_submitMetadata();
    test_encodeImage();
    test_decodeImage();
    console.log(Tag, ` out main`);
}