import "frida-il2cpp-bridge"
import Java from "frida-java-bridge"
Il2Cpp.perform(()=>{
    const all_asm = Il2Cpp.domain.assemblies
    //dict daata:  System.Collections.Generic.Dictionary`2[System.String,System.Object]
    for(const asm of all_asm){
        //const asm = Il2Cpp.domain.assembly("System")
        const all_cls = asm.image.classes
        for(const klass of all_cls){
           // const klass = Il2Cpp.domain.assembly("System").image.class("Collections.Generic.Dictionary")
           //if(String(klass.fullName).includes("Dictionary`2")){
           if(String(klass.fullName).includes("DictionaryEnumerator")){
                console.log("found class: ",klass.generics,klass.name, " at ",klass.assemblyName)
           }
            const meths = klass.methods

            for(const meth of meths){
                if(meth.name.includes(/*"Send"*/"GetBytes")){
                    //console.log("attaching: ",meth.name)
                    try{
                        Interceptor.attach(meth.virtualAddress,{
                        onEnter(args){
                            const str1 = new Il2Cpp.String(args[1])

                            if((asm.name!=="UnityEngine.UIModule")&&(asm.name!=="UnityEngine.UI")){
                                if(String(str1).includes("appversion=14.4.210")){
                                    console.log("\n\nmethod is: ",`${asm.name}/${klass.name}->${meth.name}(${meth.parameters}): \n${str1}`)
                                    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .map(DebugSymbol.fromAddress)
                                    .join("\n");

                                    console.log("\n[+] IL2CPP function called by:");
                                    console.log(bt);
                                    const caller = (this.context as any).lr ;
                                    console.log(`   caller: ${caller}`);
                                    const module = Process.findModuleByAddress(caller) as any;
                                    console.log(module.name,caller.sub(module.base));
                                }
                                
                            }
                            
                        }
                    })
                    }
                    catch(err){
                        console.log("error at: ",klass.name,"/",meth.name)
                    }
                    
                }
            }
        }
    }

    console.log("finished attaching all")
})