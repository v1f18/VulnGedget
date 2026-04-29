package org.vulngedget.visitor;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.util.Opcode;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.vulngedget.cache.DataCache.*;

//当测试的系统不为SpringBoot框架时，需要主动配置source，在source.yaml中配置
public class CustomAllClassVisitor extends ClassVisitor {
    private byte[] data;

    private String className;
    private ClassReference classReference;

    public CustomAllClassVisitor(byte[] d) {
        super(Opcode.ASM_V);
        data = d;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        this.className = name;
        this.classReference = new ClassReference();
        classReference.interfacesList = Arrays.asList(interfaces);
        classReference.className = name;
        classReference.superClassName = superName;
        if ((access & Opcodes.ACC_INTERFACE) !=0){
            classReference.isInterface = true;
        }
        mapAllClass.put(className,classReference);
        //todo

        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        for (String annotation : customClassAnnotationSource.keySet()) {
            Map<String, String> name2value = customClassAnnotationSource.get(annotation);
            if (descriptor.equals(annotation)){
                return new AnnotationVisitor(api) {
                    @Override
                    public void visit(String name, Object value) {
                        for (String s : name2value.keySet()) {
                            if (s.equals("*")){
                                allControllerClass.add(classReference);
                                break;
                            }
                                if (s.equals(name) && (name2value.get(s).equals("*") || name2value.get(s).equals(value))){
                                    allControllerClass.add(classReference);
                                    break;
                                }

                        }
                        super.visit(name, value);
                    }
                };
            }
        }
        return super.visitAnnotation(descriptor, visible);
    }


    @Override
    //这个方法是asm用来分析类中方法的
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodReference methodReference = new MethodReference();
        methodReference.className = className;
        methodReference.methodName = name;
        methodReference.desc = descriptor;
        if (isCustomSourceMethod(className, name, descriptor)) {
            methodReference.isControllerMethod = true;
        }
        allMethodReferenceList.add(methodReference);
        classReference.methodList.add(methodReference);
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (!name.equals("<clinit>")) {
            return new CustomAllClassMethodVisitor(api, methodVisitor, methodReference);
        }
        return methodVisitor;
    }

    private class CustomAllClassMethodVisitor extends MethodVisitor {

        private MethodReference methodReference;
        private String method;

        public CustomAllClassMethodVisitor(int api, MethodVisitor methodVisitor, MethodReference methodReference) {
            super(api, methodVisitor);
            this.methodReference = methodReference;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {

            for (String annotation : customMethodAnnotationSource.keySet()) {
                if (descriptor.equals(annotation)){
                    Map<String, String> name2value = customMethodAnnotationSource.get(annotation);
                        return new AnnotationVisitor(api) {
                            @Override
                            public void visit(String name, Object value) {
                                for (String s : name2value.keySet()) {
                                    if (s.equals("*")){
                                        methodReference.isControllerMethod = true;
                                        break;
                                    }
                                    if (s.equals(name) && (name2value.get(s).equals("*") || name2value.get(s).equals(value))){
                                        methodReference.isControllerMethod = true;
                                        break;
                                    }

                                }
                                super.visit(name, value);
                            }
                        };
                    }


            }
            return super.visitAnnotation(descriptor, visible);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            MethodReference m = new MethodReference();
            m.className = owner;
            m.methodName = name;
            m.desc = descriptor;
            methodReference.calledMethodList.add(m);
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }



    @Override
    public void visitEnd() {
        classResources.put(className,data);
        super.visitEnd();
    }
}
