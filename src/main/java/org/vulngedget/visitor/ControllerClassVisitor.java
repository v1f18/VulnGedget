package org.vulngedget.visitor;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.vulngedget.reference.PathReference;
import org.vulngedget.util.Opcode;

import java.util.ArrayList;

import static org.vulngedget.cache.DataCache.classPath;
import static org.vulngedget.cache.DataCache.methodPath;

public class ControllerClassVisitor extends ClassVisitor {

    public String className;
    public ControllerClassVisitor() {
        super(Opcode.ASM_V);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        className = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        ArrayList paths = new ArrayList();
        classPath.put(className,paths);
        if (descriptor.contains("RequestMapping")){
            return new AnnotationVisitor(api) {
                @Override
                public AnnotationVisitor visitArray(String name) {
                    if (name.equals("value") || name.equals("path")){
                        return new AnnotationVisitor(Opcodes.ASM6) {
                            @Override
                            public void visit(String name, Object value) {
                                paths.add(value);
                                super.visit(name, value);
                            }
                        };
                    }
                    return super.visitArray(name);
                }
            };
        }
        return super.visitAnnotation(descriptor, visible);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        return new MethodVisitor(api) {
            @Override
            public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                PathReference pathReference = new PathReference();
                pathReference.className = className;
                pathReference.methodName = name;
                methodPath.add(pathReference);
                return new AnnotationVisitor(api) {
                    @Override
                    public AnnotationVisitor visitArray(String name) {
                        if (name.equals("value") || name.equals("path")){
                            return new AnnotationVisitor(Opcodes.ASM6) {
                                @Override
                                public void visit(String name, Object value) {
                                    pathReference.paths.add(value);
                                    super.visit(name, value);
                                }
                            };
                        }
                        return super.visitArray(name);
                    }
                };
            }


            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        };
    }
}
