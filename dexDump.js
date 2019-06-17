'use strict';

/**
 * Author: guoqiangck
 * Create: 2019/6/11
 * Dump dex file for packaged apk
 * Hook art/runtime/dex_file.cc OpenMemory or OpenCommon
 * Support Version: Android 4.4 and later versions
 */

function LogPrint(log) {
    var theDate = new Date();
    var hour = theDate.getHours();
    var minute = theDate.getMinutes();
    var second = theDate.getSeconds();
    var mSecond = theDate.getMilliseconds()

    hour < 10 ? hour = "0" + hour : hour;
    minute < 10 ? minute = "0" + minute : minute;
    second < 10 ? second = "0" + second : second;
    mSecond < 10 ? mSecond = "00" + mSecond : mSecond < 100 ? mSecond = "0" + mSecond : mSecond;

    var time = hour + ":" + minute + ":" + second + ":" + mSecond;
    console.log("[" + time + "] " + log);
}

function getAndroidVersion(){
    var version = 0;

    if(Java.available){
        var versionStr = Java.androidVersion;
        version = versionStr.slice(0,1);
    }else{
        LogPrint("Error: cannot get android version");
    }
    LogPrint("Android Version: " + version);
    return version;
}

function getFunctionName(){
    var i = 0;
    var functionName = "";

    // Android 4: hook dvmDexFileOpenPartial
    // Android 5: hook OpenMemory
    // after Android 5: hook OpenCommon
    if(getAndroidVersion() > 4){ // android 5 and lasted version
        var artExports =  Module.enumerateExportsSync("libart.so");
        for(i = 0; i< artExports.length; i++){
            if(artExports[i].name.indexOf("OpenMemory") !== -1){
                functionName = artExports[i].name;
                LogPrint("index " + i + " function name: "+ functionName);
                break;
            }else if(artExports[i].name.indexOf("OpenCommon") !== -1){
                functionName = artExports[i].name;
                LogPrint("index " + i + " function name: "+ functionName);
                break;
            }
        }
    }else{ //android 4
        var dvmExports =  Module.enumerateExportsSync("libdvm.so");
        if(dvmExports.length !== 0){  // check libdvm.so first
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("dexFileParse") !== -1){
                    functionName = dvmExports[i].name;
                    LogPrint("index " + i + " function name: "+ functionName);
                    break;
                }
            }
        }else{ // if not load libdvm.so, check libart.so
            dvmExports = Module.enumerateExportsSync("libart.so");
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("OpenMemory") !== -1){
                    functionName = dvmExports[i].name;
                    LogPrint("index " + i + " function name: "+ functionName);
                    break;
                }
            }
        }
    }
    return functionName;
}

function getProcessName(){
    var processName = "";

    var fopenPtr = Module.findExportByName("libc.so", "fopen");
    var fopenFunc = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgetsFunc = new NativeFunction(fgetsPtr, 'int', ['pointer', 'int', 'pointer']);

    var pathPtr = Memory.allocUtf8String("/proc/self/cmdline");
    var openFlagsPtr = Memory.allocUtf8String("r");

    var fp = fopenFunc(pathPtr, openFlagsPtr);
    if(fp.isNull() === false){
        var buffData = Memory.alloc(128);
        var ret = fgetsFunc(buffData, 128, fp);
        if(ret !== 0){
            processName = Memory.readCString(buffData);
            LogPrint("processName " + processName);
        }
    }
    return processName;
}

function arraybuffer2hexstr(buffer)
{
    var hexArr = Array.prototype.map.call(
        new Uint8Array(buffer),
        function (bit) {
            return ('00' + bit.toString(16)).slice(-2)
        }
    );
    return hexArr.join(' ');
}

function checkDexMagic(dataAddr){
    var checkHeadHexStr = "64 65 78 0a";
    var magicFlagHexStr = "64 65 78 0a 30 33 35 00";

    var magicBuff = Memory.readByteArray(dataAddr, 4);
    var magicBuffHexStr = arraybuffer2hexstr(magicBuff);

    if(magicBuffHexStr === checkHeadHexStr){
        magicBuff = Memory.readByteArray(dataAddr, 8);
        magicBuffHexStr = arraybuffer2hexstr(magicBuff);
    }

    LogPrint("check dex magicBuffHexStr: " + magicBuffHexStr);
    return magicFlagHexStr === magicBuffHexStr;
}

function checkOdexMagic(dataAddr){
    var checkHeadHexStr = "64 65 79 0a";
    var magicFlagHexStr = "64 65 79 0a 30 33 36 00";

    var magicBuff = Memory.readByteArray(dataAddr, 4);
    var magicBuffHexStr = arraybuffer2hexstr(magicBuff);

    if(magicBuffHexStr === checkHeadHexStr){
        magicBuff = Memory.readByteArray(dataAddr, 8);
        magicBuffHexStr = arraybuffer2hexstr(magicBuff);
    }

    LogPrint("check odex magicBuffHexStr: " + magicBuffHexStr);
    return magicFlagHexStr === magicBuffHexStr;
}

function dumpDex(moduleFuncName, processName){
    if(moduleFuncName !== ""){
        var hookFunction;
        if(getAndroidVersion() > 4){ // android 5 and lasted version
            hookFunction = Module.findExportByName("libart.so", moduleFuncName);
        }else{ // android 4
            hookFunction = Module.findExportByName("libdvm.so", moduleFuncName);  // check libdvm.so first
            if(hookFunction == null) {
                hookFunction = Module.findExportByName("libart.so", moduleFuncName); //// if not load libdvm.so, check libart.so
            }
        }
        Interceptor.attach(hookFunction,{
            onEnter: function(args){
                var begin = 0;
                var dexMagicMatch = false;
                var odexMagicMatch = false;

                dexMagicMatch = checkDexMagic(args[0]);
                if(dexMagicMatch === true){
                    begin = args[0];
                }else{
                    odexMagicMatch = checkOdexMagic(args[0]);
                    if(odexMagicMatch === true){
                        begin = args[0];
                    }
                }

                if(begin === 0){
                    dexMagicMatch = checkDexMagic(args[1]);
                    if(dexMagicMatch === true){
                        begin = args[1];
                    }else{
                      odexMagicMatch = checkOdexMagic(args[1]);
                      if(odexMagicMatch === true){
                          begin = args[1];
                      }
                    }
                }

                if(dexMagicMatch === true){
                    LogPrint("magic : " + Memory.readUtf8String(begin));
                    //console.log(hexdump(begin, { offset: 0, header: false, length: 64, ansi: false }));
                    var address = parseInt(begin,16) + 0x20;
                    var dex_size = Memory.readInt(ptr(address));
                    LogPrint("dex_size :" + dex_size);
                    var dex_path = "/data/data/" + processName + "/" + dex_size + ".dex";
                    var dex_file = new File(dex_path, "wb");
                    dex_file.write(Memory.readByteArray(begin, dex_size));
                    dex_file.flush();
                    dex_file.close();
                    LogPrint("dump dex success, saved path: " + dex_path + "\n");
                }else if(odexMagicMatch === true){
                    LogPrint("magic : " + Memory.readUtf8String(begin));
                    //console.log(hexdump(begin, { offset: 0, header: false, length: 64, ansi: false }));
                    var address = parseInt(begin,16) + 0x0C;
                    var odex_size = Memory.readInt(ptr(address));
                    LogPrint("odex_size :" + odex_size);
                    var odex_path = "/data/data/" + processName + "/" + odex_size + ".odex";
                    var odex_file = new File(odex_path, "wb");
                    odex_file.write(Memory.readByteArray(begin, odex_size));
                    odex_file.flush();
                    odex_file.close();
                    LogPrint("dump odex success, saved path: " + odex_path + "\n");
                }
            },
            onLeave: function(retval){
            }
        });
    }else{
	    LogPrint("Error: cannot find correct module function.");
    }
}

//start dump dex file
var moduleFucntionname = getFunctionName();
var processName = getProcessName();
if(moduleFucntionname !== "" && processName !== ""){
    dumpDex(moduleFucntionname, processName);
}
