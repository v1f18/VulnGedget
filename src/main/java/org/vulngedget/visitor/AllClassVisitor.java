package org.vulngedget.visitor;

import org.objectweb.asm.*;

import org.vulngedget.reference.*;
import org.vulngedget.util.AnnotationUtil;
import org.vulngedget.util.Opcode;

import java.util.*;
import static org.vulngedget.cache.DataCache.*;

/**
 * A controller class needs to satisfy
 * in class: @controller @RestController [@RequestMapping]
 * in method @*Mapping [@RequestMapping, @GetMapping, @PostMapping, @PutMapping...]
 */
public class AllClassVisitor extends ClassVisitor {

    private String className;
    private ClassReference classReference;
    //obj -> [path]

    private byte[] data;


    public AllClassVisitor(byte[] d) {
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
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        //is controller class
        List<String> annontaionDescList = AnnotationUtil.controllerClassAnnotaionDescList;
        for (String annotationDesc : annontaionDescList) {
            if (annotationDesc.equals(descriptor)) {
                if (!allControllerClass.contains(classReference)){
                 allControllerClass.add(classReference);
                }
                break;
            }
        }

        return super.visitAnnotation(descriptor, visible);
    }


    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        /**
         * add method
         */
        MethodReference methodReference = new MethodReference();
        methodReference.className = className;
        methodReference.methodName = name;
        methodReference.desc = descriptor;
        allMethodReferenceList.add(methodReference);
        classReference.methodList.add(methodReference);
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (!name.equals("<clinit>")) {
            //todo
            return new AllClassMethodVisitor(api, methodVisitor, methodReference);
        }
        return methodVisitor;
    }

    @Override
    public void visitEnd() {
        classResources.put(className,data);
        super.visitEnd();
    }

    private class AllClassMethodVisitor extends MethodVisitor {

        private MethodReference methodReference;
        private List<MethodReference> calledMethods;
        private String method;

        public AllClassMethodVisitor(int api, MethodVisitor methodVisitor, MethodReference methodReference) {
            super(api, methodVisitor);
            this.methodReference = methodReference;
            this.calledMethods = new ArrayList<>();
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            if (descriptor.toLowerCase().contains("mapping")){
                methodReference.isControllerMethod = true;
            }
            return super.visitAnnotation(descriptor, visible);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            MethodReference m = new MethodReference();
            m.className = owner;
            m.methodName = name;
            m.desc = descriptor;
            calledMethods.add(m);
            methodReference.calledMethodList.add(m);
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
