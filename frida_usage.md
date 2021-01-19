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
	        
### 三、frida 通过反射获取所有成员变量（这个用例困扰了很久）
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
	
### 五、如果同一个类中存在同名函数，可以通过函数参数进行类型匹配获取该方法
```js    
    1 	function dynamic_search_method(io_object, iv_name, iv_ret_type, it_par){ 
    2 	    var lt_methods = io_object.getMethods()  ;
    3 	    var lv_found;
    4 	    for(var lv_i=0; lv_i < lt_methods.length; lv_i++){
    5 	        console.log("name:" + lt_methods[lv_i].getName().toString() + ", ret:" + lt_methods[lv_i].getGenericReturnType().toString());
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
