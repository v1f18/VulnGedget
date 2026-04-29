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

public class SpringBootControllerClassVisitor extends ClassVisitor {

    public String className;
    public SpringBootControllerClassVisitor() {
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
        //杩欓噷鍋氫簡涓€浜涗笉鍚屾敞瑙ｇ殑璺緞鍊艰幏鍙栨柟寮? 鏆傛椂鍙仛浜哛equestMapping
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
            //鏂规硶涓殑閭ｄ簺浠apping缁撳熬鐨勮矾寰勫€奸兘鍙互鐢ㄤ笅闈㈢殑鏂瑰紡鏉ヨ幏鍙?閮藉樊涓嶅
            public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                if (!descriptor.endsWith("Mapping;")) {
                    return super.visitAnnotation(descriptor, visible);
                }
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
        };
    }
}


