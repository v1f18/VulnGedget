package org.vulngedget.flows;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.tree.MethodNode;
import org.vulngedget.util.Opcode;

import java.util.HashMap;

public class FlowsClassVisitor extends ClassVisitor {
    public FlowsClassVisitor() {
        super(Opcode.ASM_V);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        return new TaintTrackingMethodVisitor<>();
    }
}
