'use strict';

/**
 * Author: guoqiangck
 * Created: 2019/6/11
 * Dump dex file for packed apks
 * Hook art/runtime/dex_file.cc OpenMemory or OpenCommon
 * Support Version: Android 4.4 up to Android 9.0
 */

function logPrint(log) {
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
        var version = parseInt(Java.androidVersion);
    }else{
        logPrint("Error: cannot get android version");
    }
    logPrint("Android Version: " + version);
    return version;
}

function getFunctionName(){
    var i = 0;
    var functionName = "";

    // Android 4: hook dvmDexFileOpenPartial
    // Android 5: hook OpenMemory
    // after Android 5: hook OpenCommon
    if(getAndroidVersion() > 4){ // android 5 and later version
        var artExports =  Module.enumerateExportsSync("libart.so");
        for(i = 0; i< artExports.length; i++){
            if(artExports[i].name.indexOf("OpenMemory") !== -1){
                functionName = artExports[i].name;
                logPrint("index " + i + " function name: "+ functionName);
                break;
            }else if(artExports[i].name.indexOf("OpenCommon") !== -1){
                functionName = artExports[i].name;
                logPrint("index " + i + " function name: "+ functionName);
                break;
            }
        }
    }else{ //android 4
        var dvmExports =  Module.enumerateExportsSync("libdvm.so");
        if(dvmExports.length !== 0){  // check libdvm.so first
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("dexFileParse") !== -1){
                    functionName = dvmExports[i].name;
                    logPrint("index " + i + " function name: "+ functionName);
                    break;
                }
            }
        }else{ // if not load libdvm.so, check libart.so
            dvmExports = Module.enumerateExportsSync("libart.so");
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("OpenMemory") !== -1){
                    functionName = dvmExports[i].name;
                    logPrint("index " + i + " function name: "+ functionName);
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
    var fclosePtr = Module.findExportByName("libc.so", "fclose");
    var fcloseFunc = new NativeFunction(fclosePtr, 'int', ['pointer']);

    var pathPtr = Memory.allocUtf8String("/proc/self/cmdline");
    var openFlagsPtr = Memory.allocUtf8String("r");

    var fp = fopenFunc(pathPtr, openFlagsPtr);
    if(fp.isNull() === false){
        var buffData = Memory.alloc(128);
        var ret = fgetsFunc(buffData, 128, fp);
        if(ret !== 0){
            processName = Memory.readCString(buffData);
            logPrint("processName " + processName);
        }
        fcloseFunc(fp);
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
    var magicMatch = true;
    var magicFlagHex = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00];

    for(var i = 0; i < 8; i++){
        if(Memory.readU8(ptr(dataAddr).add(i)) !== magicFlagHex[i]){
            magicMatch = false;
            break;
        }
    }

    return magicMatch;
}

function checkOdexMagic(dataAddr){
    var magicMatch = true;
    var magicFlagHex = [0x64, 0x65, 0x79, 0x0a, 0x30, 0x33, 0x36, 0x00];

    for(var i = 0; i < 8; i++){
        if(Memory.readU8(ptr(dataAddr).add(i)) !== magicFlagHex[i]){
            magicMatch = false;
            break;
        }
    }

    return magicMatch;
}
function dumpDexToFile(isDex, begin, processName) {
    //console.log(hexdump(begin, { offset: 0, header: false, length: 64, ansi: false }));
    var dexType;
    isDex ? dexType = "dex" : dexType = "odex";
    var magic = Memory.readUtf8String(begin).replace(/\n/g, '');
    var address = ptr(begin).add(isDex ? 0x20 : 0x1C);
    var dex_size = Memory.readInt(ptr(address));
    var dex_path = "/data/data/" + processName + "/" + dex_size + "." + dexType;
    var dex_file = new File(dex_path, "wb");

    dex_file.write(Memory.readByteArray(begin, dex_size));
    dex_file.flush();
    dex_file.close();

    logPrint("magic : " + magic );
    logPrint(dexType + "_size :" + dex_size);
    logPrint("dump " + dexType + " success, saved path: " + dex_path + "\n");
}

function dumpDex(moduleFuncName, processName){
    if(moduleFuncName !== ""){
        var hookFunction;
        if(getAndroidVersion() > 4){
            hookFunction = Module.findExportByName("libart.so", moduleFuncName);
        }else{
            hookFunction = Module.findExportByName("libdvm.so", moduleFuncName);
            if(hookFunction == null) {
                hookFunction = Module.findExportByName("libart.so", moduleFuncName);
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
                    dumpDexToFile(dexMagicMatch, begin, processName);
                } else if(odexMagicMatch === true){
                    dumpDexToFile(odexMagicMatch, begin, processName);
                }
            },
            onLeave: function(retval){
            }
        });
    }else{
	    logPrint("Error: cannot find correct module function.");
    }
}

// Main code
var moduleFucntionName = getFunctionName();
var processName = getProcessName();

if(moduleFucntionName !== "" && processName !== ""){
    dumpDex(moduleFucntionName, processName);
}
