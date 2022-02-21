### 一、遍历java类的方法和成员（非实例）
```js
    1 	function describeJavaClass(className) {
    2 	  var jClass = Java.use(className);
    3 	  console.log(JSON.stringify({
    4 	    _name: className,
    5 	    _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
    6 	      return !m.startsWith('$') // filter out Frida related special properties
    7 	         || m == 'class' || m == 'constructor' // optional
    8 	    }), 
    9 	    _fields: jClass.class.getFields().map(f => {
   10 	      return f.toString()
   11 	    })  
   12 	  }, null, 2));
   13 	}
```

### 二、frida hook java类
该方法从java的内存中获取所有的匹配该类型的instance，类似于强制搜索。
```js
    1 	//Find an instance of the class and call "secret" function.
    2 	Java.choose("com.example.my_activity", {
    3 	        onMatch: function (instance) {
    4 	                console.log("Found instance: " + instance);
    5 	                console.log("Result of secret func: " + instance.secret());
    6 	        },
    7 	        onComplete: function () { }
    8 	});
```
	        
### 三、frida 通过反射获取实例所有成员变量
```js
    1 	var fields = Java.cast(this.getClass(),Java.use('java.lang.Class')).getDeclaredFields();
    2 	console.log(fields);
    3 	for (var i = 0; i < fields.length; i++) {
    4 	        var field = fields[i];
    5 	        field.setAccessible(true);
    6 	        var name = field.getName();
    7 	        var value = field.get(this)
    8 	        console.log("name:"+name+"\tvalue:"+value);
    9 	}
```
原因是我将这段代码通过函数XX来表达，但是XX被调用的时候提示：
出错代码：
```js
    1 	function describeJavaInstance(className) {
    2 	        // console.log((new Date().getTime()) + "|" + ">>>> >>>> data of instance(" + className + "):");
    3 	        var fields = Java.cast(this.getClass(),Java.use('java.lang.Class')).getDeclaredFields();
    4 	        console.log(fields);
    5 	        for (var i = 0; i < fields.length; i++) {
    6 	                var field = fields[i];
    7 	                field.setAccessible(true);
    8 	                var name = field.getName();
    9 	                var value = field.get(this)
   10 	                console.log("name:"+name+"\tvalue:"+value);
   11 	        }
   12 	}
```
运行时报错：
```bash
    1 	{'type': 'error', 'description': "TypeError: cannot read property 'getClass' of undefined", 'stack': "TypeError: cannot read property 'getClass' of undefined\n    at describeJavaInstance (/script1.js:18)\n    at <anonymous> (/script1.js:384)\n    at apply (native)\n    at ne (frida/node_modules/frida-java-bridge/lib/class-factory.js:613)\n    at <anonymous> (frida/node_modules/frida-java-bridge/lib/class-factory.js:592)", 'fileName': '/script1.js', 'lineNumber': 18, 'columnNumber': 1}
```
解决方法：
在需要引用describeJavaInstance()的代码处，更改为describeJavaInstance()的函数主体，不要封装成函数调用。

### 四、打印字节数组
```js
    1 	function encodeHex(byteArray) {
    2 	    const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
    3 	    const StringClass = Java.use('java.lang.String');
    4 	    const hexChars = HexClass.encodeHex(byteArray);
    5 	    return StringClass.$new(hexChars).toString();
    6 	}
```	
	
### 五、如果同一个类中存在同名函数，如何过滤？
可以通过函数参数进行类型匹配获取该方法。
```js    
    1 	function dynamic_search_method(io_object, iv_name, iv_ret_type, it_par){ 
    2 	    var lt_methods = io_object.getMethods()  ;
    3 	    var lv_found;
    4 	    for(var lv_i=0; lv_i < lt_methods.length; lv_i++){
    6 	        //if (lt_methods[lv_i].getName().toString() == iv_name && lt_methods[lv_i].getGenericReturnType().toString() == iv_ret_type){
    7 	        if (lt_methods[lv_i].getName().toString() == iv_name) {
    8 	            var lt_par_type = lt_methods[lv_i].getParameterTypes();
    9 	            console.log("1:" + lt_par_type.length + ", 2:" + it_par.length);
   10 	            if(lt_par_type.length == it_par.length){
   11 	                lv_found = true; 
   12 	                for(var lv_j = 0; lv_j < lt_par_type.length && lv_found == true; lv_j++) {
   13 	                    if (lt_par_type[lv_j].getName().toString() != it_par[lv_j]) {
   14 	                        lv_found = false;
   15 	                    } 
   16 	                }                   
   17 	                if (lv_found == true) {
   18 	                    return lt_methods[lv_i];
   19 	                } else {
   20 	                }
   21 	            }
   22 	        }
   23 	    }
   24 	    return null;
   25 	}
   26 	function dynamic_invoke(io_object, io_method, it_par){
   27 	    var Java_lang_Object = Java.use('java.lang.Object');
   28 	    if(io_object===null || io_method ===null ) return null;
   29 	    try{
   30 	      var lo_cast_obj = Java.cast( io_object, Java_lang_Object);
   31 	    }catch(e){
   32 	      return null;
   33 	    }
   34 	    var lt_par = Java.array('java.lang.Object',it_par);
   35 	    return io_method.invoke(lo_cast_obj,lt_par);
   36 	}
```
如何调用？
```js
        var b_meth = dynamic_search_method(jODgb.class, "b", "java.lang.String", ["int"]);
        console.log((new Date().getTime()) + "|" + ">>>> soh0ro0t|D|b_meth|" + \
        "{" + b_meth + "}");

        var Integer = Java.use("java.lang.Integer");
        // 首先要加上.class获取clazz类，其次传入int的参数要用Integer.valueof(x)
        var test = dynamic_invoke(jODgb.class, b_meth, [Integer.valueOf(7)]);
```

### 六、写数据到文件
```js
js（该方法是纯js写法，如果要写如java的obj会有问题，写简单的字符串ok）:
    1 	    var file = new File("/data/data/com.xxx.yyy/ota.bin", "ab");
    2 	    file.write("data");
    4 	    file.flush();
    5 	    file.close();
```
或者
```java
java（该方法是java写法，data类型是byte array）
    1 	    function writeTextFileInJava(path, data) {
    2 	        try {
    3 	            var stream = jFileOutputStream.$new(path, true);
    4 	            stream.write(data);
    5 	        } catch (err) {
    6 	    
    7 	        }
    8 	    }
    9 	    var current = Date.now();
   10 	    writeTextFileInJava("/data/data/com.xxx.yyy/" + current + '-ota.bin', byteArrayArgX);
```
### 七、frida 同时hook多个设备
```java
# It works when there's only one device
#session = frida.get_usb_device().attach('com.test.app')

# Resolving hooking multiple devices issue since get_usb_device interface can not recongize device by servialno  
# in this case, starting frida server with binding address of '0.0.0.0:9999' firstly.
# and then redirecting traffic from device to local host using 'adb -s devId forward tcp:9999 tcp:9999'
# now we are capable to hook the device specified by @devId
session = frida.get_device_manager().add_remote_device("127.0.0.1:%s" % str(9999)).attach('com.test.app')
```

### 八、frida hook native函数
```java
假定存在testLib/testAPI接口的定义：int32_t testAPI(int32 id, some_struct *data)
其中some_struct的定义如下：
typedef struct {
    const char *filesL[500];
    const char *filesR[500];
    int fileN;
    const char *user;
    short type;
    int8_t tflag;
    int8_t sflag;
    int8_t unuse;
} some_struct;

下面hook该函数并解析some_struct数据：
function myGetPointer(address) {
    var ptr = new NativePointer(address);
    var val = ptr.readPointer();
    return val;
}

function myGetCharStar(address) {
    var ptr = new NativePointer(address);
    var val = ptr.readPointer();
    if (val)
        return val.readCString();
    else
        return null;
}

function processSomeStruct(data) {
    var buffer = Memory.readByteArray(data, 1000*8+8+8+2+1+1+1); 
    var some_struct = new DataView(buffer);

    var fileN = some_struct.getInt32(1000*8, true);
    var type = some_struct.getUint16(1000*8+8+8, true);
    var tflag = some_struct.getUint8(1000*8+8+8+2, true);
    var sflag = some_struct.getUint8(1000*8+8+8+2+1, true);
    var unuse = some_struct.getUint8(1000*8+8+8+2+1+1, true);

    var filesL = "{";
    for (var i=0;i<fileN;i++)
    { 
        var ptr_file_array_ele = myGetCharStar(data.add(i*8));;
        filesL += ptr_file_array_ele;
        if (i != fileN -1) {
            filesL += ', ';
        }
    }
    filesL += '}';
    
    var filesR = "{";
    for (var i=0;i<fileN;i++)
    { 
        var filesREle = myGetCharStar(data.add(500*8 + i*8));;
        filesR += filesREle;
        if (i != fileN -1) {
            filesR += ', ';
        }
    }
    filesR += '}';

    console.log('[+] some_struct -----------------------------');
    console.log('[+] filesL         --> ' + filesL);
    console.log('[+] filesR    --> ' + filesR);
    console.log('[+] fileN       --> 0x' + fileN.toString(16));
    console.log('[+] user      --> ' + myGetCharStar(data.add(1000*8+8)));
    console.log('[+] type      --> 0x' + type.toString(16));
    console.log('[+] tflag       --> 0x' + tflag.toString(16));
    console.log('[+] sflag     --> 0x' + sflag.toString(16));
    console.log('[+] unuse         --> 0x' + unuse.toString(16));
}

Java.perform(function () {
	setImmediate(function() {
		Interceptor.attach(Module.findExportByName("testLib.so" , "testAPI"), {
			onEnter: function(args) {
				console.log("testAPI called! args[0]:" + args[0]);
				console.log("testAPI called! args[1]:" + args[1]);
				processSomeStruct(args[1]);
			},
			onLeave:function(retval){
				console.log(retval);
			}
		});
	});
});

特别注意几点坑：
1. 指针移位 不是 直接(pointerX + offset)来表示，这种方式只是做拼接，实际上应该使用pointerX.add(offset)
2. 目前没有很好的方案解析结构体数据，临时方案可以使用DataView()，但是DataView无法读取64位数据，需要自己定义函数解决，
   另外解析结构体需要挨个设置成员偏移，所以一定要注意内存对其，不然偏移算错就错位了。
```

### 九、打印堆栈
```java
打印java堆栈：
clsLog = Java.use("android.util.Log")
clsException = Java.use("java.lang.Exception")
function printStackTrace() {
  console.log(clsLog .getStackTraceString(clsException .$new()));
}
```
### 十、frida追踪任意方法的通用代码
```js
	rpc.exports = {
		initTraceFunction: function(funcName, argTypeList) {
			if (!funcName.contains('.'))
				traceNativeFunction(funcName, argTypeList);
			else
				traceJavaFunction(funcName, argTypeList);
		},
		traceNativeFunction: function(funcName, argTypeList) {

		},
		traceJavaFunction: function(funcName, funcArgs) {
			Java.perform(function () {
				var shouldHook = true;
				var idx = funcName.lastIndexOf('.');
				if (idx && idx != funcName.length) {
					var className = funcName.substr(0, idx)
					var funcBaseName = funcName.substr(idx + 1)
					var jClazz = Java.use(className);

					for (var index in jClazz[funcBaseName].overloads) {
					
						var method_overload = jClazz[funcBaseName].overloads[index];
						
						// 该判断无效，恒为false
						//if (method_overload.hasOwnProperty('argumentTypes')) {
							var msg = "Hooking class: " + className + " Fcuntion: " + funcBaseName;
							var argTypes = [];
							var paraIndex = 0;

							for(var j in method_overload.argumentTypes) {
								argTypes.push(method_overload.argumentTypes[j].className);
							}

							// Check if we are looking for a specific overload
							if (funcArgs != undefined) {
								shouldHook = false;
								if (method_overload.argumentTypes.length == funcArgs.length) {
									var sameArgsCount = 0;
									for (var i in method_overload.argumentTypes) {
										if (method_overload.argumentTypes[i].className == funcArgs[i])
											sameArgsCount++;
										else
											break;
									}

									if (sameArgsCount == funcArgs.length) 
										shouldHook = true;
								}
							}

							if (shouldHook) {
								// 使用转义符，否则报错“SyntaxError: unexpected end of string”
								send(msg + '(' + argTypes.toString() + ')\\n');
								try {
									method_overload.implementation = function() {
										var args = [].slice.call(arguments)
										var result = this[funcBaseName].apply(this, args);
										var rstr = result.toString();
										var delimiter = "|";
										var msg = delimiter + className + delimiter + funcBaseName + '(' + args.join(', ') + ') => return: ' + rstr;
										sendLog(msg);
										sendCallingStack();
										return result;
									}
								} catch(e) {
									sendError("Hook ERROR: " + e);
								}
							}
						//}
					}
				}
			})
		}	
	}	
```
```js
script.exports.trace_java_function("android.app.Activity.startActivity", ["android.content.Intent"])
script.exports.trace_java_function("java.io.InputStream.read", ["[B", "int", "int"]);
script.exports.trace_java_function("android.text.TextUtils.equals", ["java.lang.CharSequence", "java.lang.CharSequence"])
```

### 十、打印intent
```js
	function showIntent(intent) {
		var data = intent.getData();
		sendDebug(delimiter + "show intent" + delimiter + intent.toString());
		sendDebug(delimiter + 'show intent data' + delimiter + data);

		var bundle = intent.getExtras();
		if (bundle != null) {
			var str = '\\n\\t{\\n';
			var keys = bundle.keySet();
			var it = keys.iterator();
			while (it.hasNext()) {
				var key = it.next();
				str += '\\t\\t' + key;
				str += ':';
				str += bundle.get(key);
				str += "\\n";
			}
			str += '\\t}';
			sendDebug(delimiter + 'show intent extra' + delimiter + str);
		}
	}
```
### 十一、hook内部私有对象的某个回调
```js
比如开源组件RePlugin的com.qihoo360.loader2.PmBase类中存在mBroadcastReceiver私有成员，如果要hook其回调方法onReceive该怎么做？
类似于内部类，区别是内部类使用"$内部类名"进行引用，而私有成员对象使用"$数字"进行引用，比如此处事例为com.qihoo360.loader2.PmBase$1.onReceive
```

### 十二、hook某个类中所有方法
```js
function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    for (var i = 0; i < overloadCount; i++) {
		// hook function 
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString(): 'null'});
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { method: targetClassMethod, val: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            LOG(log, { c: Color.Blue});
            return retval;
        }
    }
}

function hookAllMethodsOfClass(name) {
	var hookCls = Java.use(name);
	var ownMethods = hookCls.class.getDeclaredMethods();
	ownMethods.forEach(function(method) {
		var methodStr = method.toString();
		var methodReplace = methodStr.replace(name+ ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
		var fullMethodName = name + '.' + methodReplace
		LOG({ tracing: fullMethodName, overloaded: 1}, { c: Color.Green });
		traceMethod(fullMethodName);
	});
} 
```
### 十三、使用runnable调用某个接口
// ===============================================================================================================
// android.webkit.WebView getSettings (仅能为已经存在的webview开启调试，不包括新建的webview)
// ===============================================================================================================
Java.choose("android.webkit.WebView", {
	"onMatch": function(o) {
		try {
			// Use a Runnable to invoke the setWebContentsDebuggingEnabled
			// method in the same thread as the WebView
			var Runnable = Java.use('java.lang.Runnable');
			var MyRunnable = Java.registerClass({
				name: 'com.example.MyRunnable',
				implements: [Runnable],
				methods: {
					'run': function() {
						o.setWebContentsDebuggingEnabled(true);
						console.log('[*] Switch WebView debuggable');
					}
				}
			});
			var runnable = MyRunnable.$new();
			o.post(runnable);
		} catch (e) {
			console.log("[!] execution failed: " + e.message);
		}
	},
	"onComplete": function() {
		console.log("[*] Whoa! all webview instances debuggable")
	}
})
```

### 十四、 遍历对象并打印所有的成员
```javascript
function dumpAllFieldValue(obj) {
    if (obj === null) {
        return;
    }

    console.log("Dump all fields value for  " + obj.getClass() + " :");

    var cls = obj.getClass();

    while (cls !== null && !cls.equals(Java.use("java.lang.Object").class)) {
        var fields = cls.getDeclaredFields();
        if (fields === null || fields.length === 0) {
            cls = cls.getSuperclass();
            continue;
        }

        if (!cls.equals(obj.getClass())) {
            console.log("Dump super class  " + cls.getName() + " fields:");
        }

        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            field.setAccessible(true);
            var name = field.getName();
            var value = field.get(obj);
            var type = field.getType();
            console.log(type + " " + name + "=" + value);
        }

        cls = cls.getSuperclass();
    }
}
```

### 十五、获取对象内某个成员变量的值
```js
function getFieldValue(obj, fieldName) {
    var cls = obj.getClass();
    var field = cls.getDeclaredField(fieldName);
    field.setAccessible(true);
    var name = field.getName();
    var value = field.get(obj);
    // console.log("field: " + field + "\tname:" + name + "\tvalue:" + value);
    return value;
}
```
