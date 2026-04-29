package org.vulngedget.util;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.vulngedget.reference.InvocationDetail;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.reference.PathReference;
import org.vulngedget.reference.VulnerabilityFlowDetail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.vulngedget.cache.DataCache.classPath;
import static org.vulngedget.cache.DataCache.classResources;
import static org.vulngedget.cache.DataCache.methodPath;
import static org.vulngedget.cache.DataCache.maybeVulnMapFlows;
import static org.vulngedget.cache.DataCache.url;

public class FlowDetailBuilder {

    private static final int MAX_EXPRESSION_LENGTH = Integer.getInteger("vulngadget.maxExpressionLength", 240);
    private static final Map<String, ClassNode> CLASS_NODE_CACHE = new HashMap<>();
    private static final Map<String, MethodNode> METHOD_NODE_CACHE = new HashMap<>();
    private static final Map<String, MethodMetadata> METHOD_METADATA_CACHE = new HashMap<>();
    private static final Map<String, List<InvocationDetail>> INVOCATION_CACHE = new HashMap<>();

    public static Map<String, List<VulnerabilityFlowDetail>> buildAllVulnerabilityFlowDetails() {
        LinkedHashMap<String, List<VulnerabilityFlowDetail>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<List<MethodReference>>> entry : maybeVulnMapFlows.entrySet()) {
            ArrayList<VulnerabilityFlowDetail> details = new ArrayList<>();
            for (List<MethodReference> methodPath : entry.getValue()) {
                details.add(buildFlowDetail(entry.getKey(), methodPath));
            }
            result.put(entry.getKey(), details);
        }
        return result;
    }

    public static VulnerabilityFlowDetail buildFlowDetail(String vulnType, List<MethodReference> methodPath) {
        VulnerabilityFlowDetail detail = new VulnerabilityFlowDetail();
        detail.vulnType = vulnType;
        if (methodPath == null || methodPath.isEmpty()) {
            return detail;
        }

        MethodReference entryMethod = methodPath.get(0);
        detail.url = getPath(entryMethod.className, entryMethod.methodName);
        detail.entryClassName = entryMethod.className;
        detail.entryMethodName = entryMethod.methodName;
        detail.entryDesc = entryMethod.desc;
        detail.entryParameters.addAll(resolveMethodMetadata(entryMethod).parameterExpressions);

        for (int i = 0; i < methodPath.size() - 1; i++) {
            MethodReference caller = methodPath.get(i);
            MethodReference callee = methodPath.get(i + 1);
            detail.invocations.add(resolveInvocationDetail(caller, callee));
        }
        return detail;
    }

    private static InvocationDetail resolveInvocationDetail(MethodReference caller, MethodReference callee) {
        List<InvocationDetail> candidates = resolveInvocationCandidates(caller, callee);
        if (!candidates.isEmpty()) {
            InvocationDetail selected = copyInvocationDetail(candidates.get(0));
            selected.candidateCount = candidates.size();
            return selected;
        }

        if (isSyntheticDispatch(caller, callee)) {
            return buildSyntheticDispatchDetail(caller, callee);
        }

        InvocationDetail fallback = new InvocationDetail();
        fallback.callerClassName = caller.className;
        fallback.callerMethodName = caller.methodName;
        fallback.callerDesc = caller.desc;
        fallback.calleeClassName = callee.className;
        fallback.calleeMethodName = callee.methodName;
        fallback.calleeDesc = callee.desc;
        fallback.receiver = "<unknown>";
        fallback.arguments.add("<unknown>");
        return fallback;
    }

    private static List<InvocationDetail> resolveInvocationCandidates(MethodReference caller, MethodReference callee) {
        String cacheKey = buildMethodKey(caller) + "->" + buildMethodKey(callee);
        if (INVOCATION_CACHE.containsKey(cacheKey)) {
            return INVOCATION_CACHE.get(cacheKey);
        }

        MethodNode methodNode = getMethodNode(caller);
        MethodMetadata methodMetadata = resolveMethodMetadata(caller);
        if (methodNode == null) {
            INVOCATION_CACHE.put(cacheKey, Collections.<InvocationDetail>emptyList());
            return Collections.emptyList();
        }

        ArrayList<InvocationDetail> matches = new ArrayList<>();
        try {
            Analyzer<SymbolicValue> analyzer = new Analyzer<>(new SymbolicInterpreter(methodMetadata));
            Frame<SymbolicValue>[] frames = analyzer.analyze(caller.className, methodNode);
            int currentLine = -1;
            for (int i = 0; i < methodNode.instructions.size(); i++) {
                AbstractInsnNode insnNode = methodNode.instructions.get(i);
                if (insnNode instanceof LineNumberNode) {
                    currentLine = ((LineNumberNode) insnNode).line;
                    continue;
                }
                if (!(insnNode instanceof MethodInsnNode)) {
                    continue;
                }

                MethodInsnNode methodInsnNode = (MethodInsnNode) insnNode;
                if (!methodInsnNode.owner.equals(callee.className)
                        || !methodInsnNode.name.equals(callee.methodName)
                        || !methodInsnNode.desc.equals(callee.desc)) {
                    continue;
                }

                InvocationDetail invocationDetail = buildInvocationFromFrame(
                        caller,
                        callee,
                        methodInsnNode,
                        frames[i],
                        currentLine
                );
                matches.add(invocationDetail);
            }
        } catch (AnalyzerException ignored) {
            INVOCATION_CACHE.put(cacheKey, Collections.<InvocationDetail>emptyList());
            return Collections.emptyList();
        }

        INVOCATION_CACHE.put(cacheKey, matches);
        return matches;
    }

    private static InvocationDetail buildInvocationFromFrame(MethodReference caller,
                                                             MethodReference callee,
                                                             MethodInsnNode methodInsnNode,
                                                             Frame<SymbolicValue> frame,
                                                             int currentLine) {
        InvocationDetail detail = new InvocationDetail();
        detail.callerClassName = caller.className;
        detail.callerMethodName = caller.methodName;
        detail.callerDesc = caller.desc;
        detail.calleeClassName = callee.className;
        detail.calleeMethodName = callee.methodName;
        detail.calleeDesc = callee.desc;
        detail.lineNumber = currentLine;

        if (frame == null) {
            detail.receiver = methodInsnNode.getOpcode() == Opcodes.INVOKESTATIC ? "<static>" : "<unknown>";
            detail.arguments.add("<unknown>");
            return detail;
        }

        Type[] argTypes = Type.getArgumentTypes(methodInsnNode.desc);
        boolean hasReceiver = methodInsnNode.getOpcode() != Opcodes.INVOKESTATIC;
        int stackValuesNeeded = argTypes.length + (hasReceiver ? 1 : 0);
        int stackStart = frame.getStackSize() - stackValuesNeeded;

        if (stackStart < 0) {
            detail.receiver = hasReceiver ? "<unknown>" : "<static>";
            detail.arguments.add("<unknown>");
            return detail;
        }

        int cursor = stackStart;
        if (hasReceiver) {
            detail.receiver = normalizeExpression(frame.getStack(cursor++));
        } else {
            detail.receiver = "<static>";
        }

        for (int i = 0; i < argTypes.length; i++) {
            detail.arguments.add(normalizeExpression(frame.getStack(cursor + i)));
        }
        return detail;
    }

    private static InvocationDetail buildSyntheticDispatchDetail(MethodReference caller, MethodReference callee) {
        InvocationDetail detail = new InvocationDetail();
        detail.callerClassName = caller.className;
        detail.callerMethodName = caller.methodName;
        detail.callerDesc = caller.desc;
        detail.calleeClassName = callee.className;
        detail.calleeMethodName = callee.methodName;
        detail.calleeDesc = callee.desc;
        detail.receiver = "<synthetic-dispatch>";
        detail.lineNumber = -1;
        detail.arguments.addAll(resolveMethodMetadata(caller).parameterReferences);
        if (detail.arguments.isEmpty()) {
            detail.arguments.add("<no-args>");
        }
        return detail;
    }

    private static boolean isSyntheticDispatch(MethodReference caller, MethodReference callee) {
        return caller.methodName.equals(callee.methodName)
                && caller.desc.equals(callee.desc)
                && !caller.className.equals(callee.className);
    }

    private static InvocationDetail copyInvocationDetail(InvocationDetail source) {
        InvocationDetail target = new InvocationDetail();
        target.callerClassName = source.callerClassName;
        target.callerMethodName = source.callerMethodName;
        target.callerDesc = source.callerDesc;
        target.calleeClassName = source.calleeClassName;
        target.calleeMethodName = source.calleeMethodName;
        target.calleeDesc = source.calleeDesc;
        target.receiver = source.receiver;
        target.lineNumber = source.lineNumber;
        target.arguments.addAll(source.arguments);
        return target;
    }

    private static MethodMetadata resolveMethodMetadata(MethodReference methodReference) {
        String cacheKey = buildMethodKey(methodReference);
        if (METHOD_METADATA_CACHE.containsKey(cacheKey)) {
            return METHOD_METADATA_CACHE.get(cacheKey);
        }

        MethodMetadata metadata = new MethodMetadata();
        MethodNode methodNode = getMethodNode(methodReference);
        metadata.isStatic = methodNode != null && (methodNode.access & Opcodes.ACC_STATIC) != 0;

        Type[] argTypes = Type.getArgumentTypes(methodReference.desc);
        Map<Integer, String> localNames = extractLocalNames(methodNode);
        int localIndex = metadata.isStatic ? 0 : 1;
        for (int i = 0; i < argTypes.length; i++) {
            Type argType = argTypes[i];
            String parameterName = localNames.get(localIndex);
            if (parameterName == null || parameterName.startsWith("this")) {
                parameterName = "arg" + i;
            }
            String annotationSummary = extractParameterAnnotationSummary(methodNode, i);
            String parameterExpression = parameterName + ":" + simplifyTypeName(argType);
            if (!annotationSummary.isEmpty()) {
                parameterExpression = parameterExpression + " " + annotationSummary;
            }
            metadata.parameterExpressions.add(parameterExpression);
            metadata.parameterReferences.add(parameterName);
            metadata.localExpressions.put(localIndex, parameterName);
            localIndex += argType.getSize();
        }

        if (!metadata.isStatic) {
            metadata.localExpressions.put(0, "this");
        }

        METHOD_METADATA_CACHE.put(cacheKey, metadata);
        return metadata;
    }

    private static Map<Integer, String> extractLocalNames(MethodNode methodNode) {
        HashMap<Integer, String> result = new HashMap<>();
        if (methodNode == null || methodNode.localVariables == null) {
            return result;
        }
        for (LocalVariableNode localVariableNode : methodNode.localVariables) {
            if (!result.containsKey(localVariableNode.index)) {
                result.put(localVariableNode.index, localVariableNode.name);
            }
        }
        return result;
    }

    private static String extractParameterAnnotationSummary(MethodNode methodNode, int parameterIndex) {
        if (methodNode == null) {
            return "";
        }
        ArrayList<String> result = new ArrayList<>();
        collectAnnotationSummary(methodNode.visibleParameterAnnotations, parameterIndex, result);
        collectAnnotationSummary(methodNode.invisibleParameterAnnotations, parameterIndex, result);
        if (result.isEmpty()) {
            return "";
        }
        return join(result, " ");
    }

    private static void collectAnnotationSummary(List<AnnotationNode>[] annotationGroups,
                                                 int parameterIndex,
                                                 List<String> result) {
        if (annotationGroups == null || parameterIndex >= annotationGroups.length) {
            return;
        }
        List<AnnotationNode> annotations = annotationGroups[parameterIndex];
        if (annotations == null) {
            return;
        }
        for (AnnotationNode annotationNode : annotations) {
            result.add(formatAnnotation(annotationNode));
        }
    }

    private static String formatAnnotation(AnnotationNode annotationNode) {
        String annotationName = "@" + simplifyInternalName(Type.getType(annotationNode.desc).getClassName().replace('.', '/'));
        if (annotationNode.values == null || annotationNode.values.isEmpty()) {
            return annotationName;
        }
        for (int i = 0; i < annotationNode.values.size() - 1; i += 2) {
            Object key = annotationNode.values.get(i);
            Object value = annotationNode.values.get(i + 1);
            if ("value".equals(key) || "name".equals(key) || "path".equals(key)) {
                return annotationName + "(" + literal(value) + ")";
            }
        }
        return annotationName;
    }

    private static MethodNode getMethodNode(MethodReference methodReference) {
        String cacheKey = buildMethodKey(methodReference);
        if (METHOD_NODE_CACHE.containsKey(cacheKey)) {
            return METHOD_NODE_CACHE.get(cacheKey);
        }

        ClassNode classNode = getClassNode(methodReference.className);
        if (classNode == null || classNode.methods == null) {
            METHOD_NODE_CACHE.put(cacheKey, null);
            return null;
        }

        for (Object methodObject : classNode.methods) {
            MethodNode methodNode = (MethodNode) methodObject;
            if (methodNode.name.equals(methodReference.methodName) && methodNode.desc.equals(methodReference.desc)) {
                METHOD_NODE_CACHE.put(cacheKey, methodNode);
                return methodNode;
            }
        }
        METHOD_NODE_CACHE.put(cacheKey, null);
        return null;
    }

    private static ClassNode getClassNode(String className) {
        if (CLASS_NODE_CACHE.containsKey(className)) {
            return CLASS_NODE_CACHE.get(className);
        }

        byte[] classBytes = classResources.get(className);
        if (classBytes == null) {
            CLASS_NODE_CACHE.put(className, null);
            return null;
        }

        ClassNode classNode = new ClassNode();
        ClassReader classReader = new ClassReader(classBytes);
        classReader.accept(classNode, 0);
        CLASS_NODE_CACHE.put(className, classNode);
        return classNode;
    }

    public static String getPath(String className, String methodName) {
        List classList = classPath.get(className);
        String p1 = "";
        if (classList != null && classList.size() != 0) {
            p1 = (String) classList.get(0);
        }
        String p2 = "";
        for (PathReference pathReference : methodPath) {
            if (methodName.equals(pathReference.methodName) && className.equals(pathReference.className)) {
                if (pathReference.paths != null && pathReference.paths.size() != 0) {
                    p2 = (String) pathReference.paths.get(0);
                }
                break;
            }
        }
        if (p1.startsWith("/") && p2.startsWith("/")) {
            return url + p1 + p2;
        }
        return url + "/" + p1 + p2;
    }

    public static String formatMethodSignature(String className, String methodName, String desc) {
        return className + "#" + methodName + desc;
    }

    private static String buildMethodKey(MethodReference methodReference) {
        return formatMethodSignature(methodReference.className, methodReference.methodName, methodReference.desc);
    }

    private static String normalizeExpression(SymbolicValue value) {
        if (value == null || value.getExpression() == null || value.getExpression().isEmpty()) {
            return "<unknown>";
        }
        return abbreviateExpression(value.getExpression());
    }

    private static String abbreviateExpression(String expression) {
        if (expression == null || expression.isEmpty()) {
            return "<unknown>";
        }
        if (expression.length() <= MAX_EXPRESSION_LENGTH) {
            return expression;
        }
        int side = Math.max(24, MAX_EXPRESSION_LENGTH / 2 - 12);
        return expression.substring(0, side)
                + "...(" + expression.length() + " chars)..."
                + expression.substring(expression.length() - side);
    }

    private static String literal(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return "\"" + value + "\"";
        }
        return String.valueOf(value);
    }

    private static String simplifyTypeName(Type type) {
        if (type == null) {
            return "Object";
        }
        if (type.getSort() == Type.ARRAY) {
            return simplifyTypeName(type.getElementType()) + "[]";
        }
        if (type.getSort() == Type.OBJECT) {
            return simplifyInternalName(type.getInternalName());
        }
        return type.getClassName();
    }

    private static String simplifyInternalName(String internalName) {
        if (internalName == null || internalName.isEmpty()) {
            return "Object";
        }
        int idx = internalName.lastIndexOf('/');
        return idx >= 0 ? internalName.substring(idx + 1) : internalName;
    }

    private static String join(List<String> values, String delimiter) {
        if (values.isEmpty()) {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                stringBuilder.append(delimiter);
            }
            stringBuilder.append(values.get(i));
        }
        return stringBuilder.toString();
    }

    private static class MethodMetadata {
        boolean isStatic;
        List<String> parameterExpressions = new ArrayList<>();
        List<String> parameterReferences = new ArrayList<>();
        Map<Integer, String> localExpressions = new HashMap<>();
    }

    private static class ExpressionHolder {
        String expression;

        ExpressionHolder(String expression) {
            this.expression = expression;
        }
    }

    private static class SymbolicValue extends BasicValue {
        private final ExpressionHolder holder;

        SymbolicValue(Type type, String expression) {
            this(type, new ExpressionHolder(abbreviateExpression(expression)));
        }

        SymbolicValue(Type type, ExpressionHolder holder) {
            super(type);
            this.holder = holder;
        }

        SymbolicValue alias() {
            return new SymbolicValue(getType(), holder);
        }

        String getExpression() {
            return holder.expression;
        }

        void setExpression(String expression) {
            holder.expression = abbreviateExpression(expression);
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof SymbolicValue)) {
                return false;
            }
            SymbolicValue other = (SymbolicValue) obj;
            if (getType() == null) {
                return other.getType() == null;
            }
            return getType().equals(other.getType())
                    && String.valueOf(getExpression()).equals(String.valueOf(other.getExpression()));
        }

        @Override
        public int hashCode() {
            int result = getType() == null ? 0 : getType().hashCode();
            result = 31 * result + String.valueOf(getExpression()).hashCode();
            return result;
        }
    }

    private static class SymbolicInterpreter extends Interpreter<SymbolicValue> {
        private final MethodMetadata methodMetadata;

        SymbolicInterpreter(MethodMetadata methodMetadata) {
            super(Opcode.ASM_V);
            this.methodMetadata = methodMetadata;
        }

        @Override
        public SymbolicValue newValue(Type type) {
            if (type == null) {
                return new SymbolicValue(null, "<empty>");
            }
            if (Type.VOID_TYPE.equals(type)) {
                return null;
            }
            return new SymbolicValue(type, "<" + simplifyTypeName(type) + ">");
        }

        @Override
        public SymbolicValue newParameterValue(boolean isInstanceMethod, int local, Type type) {
            String expression = methodMetadata.localExpressions.get(local);
            if (expression == null) {
                expression = "local" + local;
            }
            return new SymbolicValue(type, expression);
        }

        @Override
        public SymbolicValue newEmptyValue(int local) {
            return new SymbolicValue(null, "local" + local);
        }

        @Override
        public SymbolicValue newOperation(AbstractInsnNode insnNode) {
            switch (insnNode.getOpcode()) {
                case Opcodes.ACONST_NULL:
                    return new SymbolicValue(Type.getObjectType("java/lang/Object"), "null");
                case Opcodes.ICONST_M1:
                case Opcodes.ICONST_0:
                case Opcodes.ICONST_1:
                case Opcodes.ICONST_2:
                case Opcodes.ICONST_3:
                case Opcodes.ICONST_4:
                case Opcodes.ICONST_5:
                    return new SymbolicValue(Type.INT_TYPE, String.valueOf(insnNode.getOpcode() - Opcodes.ICONST_0));
                case Opcodes.LCONST_0:
                    return new SymbolicValue(Type.LONG_TYPE, "0L");
                case Opcodes.LCONST_1:
                    return new SymbolicValue(Type.LONG_TYPE, "1L");
                case Opcodes.FCONST_0:
                    return new SymbolicValue(Type.FLOAT_TYPE, "0.0f");
                case Opcodes.FCONST_1:
                    return new SymbolicValue(Type.FLOAT_TYPE, "1.0f");
                case Opcodes.FCONST_2:
                    return new SymbolicValue(Type.FLOAT_TYPE, "2.0f");
                case Opcodes.DCONST_0:
                    return new SymbolicValue(Type.DOUBLE_TYPE, "0.0d");
                case Opcodes.DCONST_1:
                    return new SymbolicValue(Type.DOUBLE_TYPE, "1.0d");
                case Opcodes.BIPUSH:
                case Opcodes.SIPUSH:
                    return new SymbolicValue(Type.INT_TYPE, String.valueOf(((org.objectweb.asm.tree.IntInsnNode) insnNode).operand));
                case Opcodes.LDC:
                    return new SymbolicValue(typeForLdc(((org.objectweb.asm.tree.LdcInsnNode) insnNode).cst),
                            literal(((org.objectweb.asm.tree.LdcInsnNode) insnNode).cst));
                case Opcodes.NEW:
                    String newType = ((TypeInsnNode) insnNode).desc;
                    return new SymbolicValue(Type.getObjectType(newType), "new " + simplifyInternalName(newType));
                case Opcodes.GETSTATIC:
                    FieldInsnNode fieldInsnNode = (FieldInsnNode) insnNode;
                    return new SymbolicValue(Type.getType(fieldInsnNode.desc),
                            simplifyInternalName(fieldInsnNode.owner) + "." + fieldInsnNode.name);
                default:
                    return new SymbolicValue(defaultTypeForInstruction(insnNode), "<op>");
            }
        }

        @Override
        public SymbolicValue copyOperation(AbstractInsnNode insnNode, SymbolicValue value) {
            return value == null ? null : value.alias();
        }

        @Override
        public SymbolicValue unaryOperation(AbstractInsnNode insnNode, SymbolicValue value) {
            switch (insnNode.getOpcode()) {
                case Opcodes.CHECKCAST:
                    return value == null ? null : value.alias();
                case Opcodes.GETFIELD:
                    FieldInsnNode fieldInsnNode = (FieldInsnNode) insnNode;
                    return new SymbolicValue(Type.getType(fieldInsnNode.desc),
                            normalizeExpression(value) + "." + fieldInsnNode.name);
                case Opcodes.ARRAYLENGTH:
                    return new SymbolicValue(Type.INT_TYPE, "len(" + normalizeExpression(value) + ")");
                case Opcodes.INSTANCEOF:
                    return new SymbolicValue(Type.BOOLEAN_TYPE,
                            "(" + normalizeExpression(value) + " instanceof "
                                    + simplifyInternalName(((TypeInsnNode) insnNode).desc) + ")");
                case Opcodes.ANEWARRAY:
                    return new SymbolicValue(Type.getType("[L" + ((TypeInsnNode) insnNode).desc + ";"),
                            "new " + simplifyInternalName(((TypeInsnNode) insnNode).desc)
                                    + "[" + normalizeExpression(value) + "]");
                case Opcodes.NEWARRAY:
                    return new SymbolicValue(Type.getType("[Ljava/lang/Object;"),
                            "new array[" + normalizeExpression(value) + "]");
                default:
                    return new SymbolicValue(defaultTypeForInstruction(insnNode), normalizeExpression(value));
            }
        }

        @Override
        public SymbolicValue binaryOperation(AbstractInsnNode insnNode, SymbolicValue value1, SymbolicValue value2) {
            switch (insnNode.getOpcode()) {
                case Opcodes.AALOAD:
                    return new SymbolicValue(Type.getObjectType("java/lang/Object"),
                            normalizeExpression(value1) + "[" + normalizeExpression(value2) + "]");
                case Opcodes.IADD:
                case Opcodes.LADD:
                case Opcodes.FADD:
                case Opcodes.DADD:
                    return new SymbolicValue(resultType(insnNode),
                            "(" + normalizeExpression(value1) + " + " + normalizeExpression(value2) + ")");
                case Opcodes.ISUB:
                case Opcodes.LSUB:
                case Opcodes.FSUB:
                case Opcodes.DSUB:
                    return new SymbolicValue(resultType(insnNode),
                            "(" + normalizeExpression(value1) + " - " + normalizeExpression(value2) + ")");
                case Opcodes.IMUL:
                case Opcodes.LMUL:
                case Opcodes.FMUL:
                case Opcodes.DMUL:
                    return new SymbolicValue(resultType(insnNode),
                            "(" + normalizeExpression(value1) + " * " + normalizeExpression(value2) + ")");
                case Opcodes.IDIV:
                case Opcodes.LDIV:
                case Opcodes.FDIV:
                case Opcodes.DDIV:
                    return new SymbolicValue(resultType(insnNode),
                            "(" + normalizeExpression(value1) + " / " + normalizeExpression(value2) + ")");
                default:
                    return new SymbolicValue(defaultTypeForInstruction(insnNode),
                            "(" + normalizeExpression(value1) + ", " + normalizeExpression(value2) + ")");
            }
        }

        @Override
        public SymbolicValue ternaryOperation(AbstractInsnNode insnNode,
                                             SymbolicValue value1,
                                             SymbolicValue value2,
                                             SymbolicValue value3) {
            return null;
        }

        @Override
        public SymbolicValue naryOperation(AbstractInsnNode insnNode, List<? extends SymbolicValue> values) {
            if (insnNode instanceof MethodInsnNode) {
                MethodInsnNode methodInsnNode = (MethodInsnNode) insnNode;
                return handleMethodInvocation(methodInsnNode, values);
            }
            if (insnNode instanceof InvokeDynamicInsnNode) {
                return handleInvokeDynamic((InvokeDynamicInsnNode) insnNode, values);
            }
            return new SymbolicValue(defaultTypeForInstruction(insnNode), "<invoke>");
        }

        @Override
        public void returnOperation(AbstractInsnNode insnNode, SymbolicValue value, SymbolicValue expected) {
        }

        @Override
        public SymbolicValue merge(SymbolicValue value1, SymbolicValue value2) {
            if (value1 == null) {
                return value2;
            }
            if (value2 == null) {
                return value1;
            }
            if (value1.equals(value2)) {
                return value1;
            }
            Type mergedType = mergeType(value1.getType(), value2.getType());
            String mergedExpression = mergeExpression(value1.getExpression(), value2.getExpression());
            return new SymbolicValue(mergedType, mergedExpression);
        }

        private SymbolicValue handleMethodInvocation(MethodInsnNode methodInsnNode, List<? extends SymbolicValue> values) {
            Type returnType = Type.getReturnType(methodInsnNode.desc);
            boolean isStatic = methodInsnNode.getOpcode() == Opcodes.INVOKESTATIC;
            SymbolicValue receiver = isStatic ? null : values.get(0);
            int argOffset = isStatic ? 0 : 1;
            ArrayList<String> args = new ArrayList<>();
            for (int i = argOffset; i < values.size(); i++) {
                args.add(normalizeExpression(values.get(i)));
            }

            if ("<init>".equals(methodInsnNode.name)) {
                if (receiver != null) {
                    receiver.setExpression("new " + simplifyInternalName(methodInsnNode.owner)
                            + "(" + join(args, ", ") + ")");
                }
                return null;
            }

            if (isStringBuilder(methodInsnNode.owner)) {
                if ("append".equals(methodInsnNode.name) && receiver != null && !args.isEmpty()) {
                    receiver.setExpression("(" + normalizeExpression(receiver) + " + " + args.get(0) + ")");
                    return receiver.alias();
                }
                if ("toString".equals(methodInsnNode.name) && receiver != null) {
                    return new SymbolicValue(Type.getObjectType("java/lang/String"), normalizeExpression(receiver));
                }
            }

            if ("java/lang/String".equals(methodInsnNode.owner) && "valueOf".equals(methodInsnNode.name) && !args.isEmpty()) {
                return new SymbolicValue(Type.getObjectType("java/lang/String"), args.get(0));
            }

            if ("java/lang/String".equals(methodInsnNode.owner) && "concat".equals(methodInsnNode.name)
                    && receiver != null && !args.isEmpty()) {
                return new SymbolicValue(Type.getObjectType("java/lang/String"),
                        "(" + normalizeExpression(receiver) + " + " + args.get(0) + ")");
            }

            if ("java/util/Objects".equals(methodInsnNode.owner) && "toString".equals(methodInsnNode.name)
                    && !args.isEmpty()) {
                return new SymbolicValue(returnType, args.get(0));
            }

            String callExpression;
            if (receiver == null) {
                callExpression = simplifyInternalName(methodInsnNode.owner) + "." + methodInsnNode.name
                        + "(" + join(args, ", ") + ")";
            } else {
                callExpression = normalizeExpression(receiver) + "." + methodInsnNode.name
                        + "(" + join(args, ", ") + ")";
            }
            return returnType == Type.VOID_TYPE ? null : new SymbolicValue(returnType, callExpression);
        }

        private SymbolicValue handleInvokeDynamic(InvokeDynamicInsnNode invokeDynamicInsnNode,
                                                  List<? extends SymbolicValue> values) {
            ArrayList<String> args = new ArrayList<>();
            for (SymbolicValue value : values) {
                args.add(normalizeExpression(value));
            }
            String name = invokeDynamicInsnNode.name;
            if (name != null && name.toLowerCase().contains("concat")) {
                return new SymbolicValue(Type.getReturnType(invokeDynamicInsnNode.desc),
                        "(" + join(args, " + ") + ")");
            }
            return new SymbolicValue(Type.getReturnType(invokeDynamicInsnNode.desc),
                    "invokedynamic(" + join(args, ", ") + ")");
        }

        private boolean isStringBuilder(String owner) {
            return "java/lang/StringBuilder".equals(owner) || "java/lang/StringBuffer".equals(owner);
        }

        private Type resultType(AbstractInsnNode insnNode) {
            switch (insnNode.getOpcode()) {
                case Opcodes.LADD:
                case Opcodes.LSUB:
                case Opcodes.LMUL:
                case Opcodes.LDIV:
                    return Type.LONG_TYPE;
                case Opcodes.FADD:
                case Opcodes.FSUB:
                case Opcodes.FMUL:
                case Opcodes.FDIV:
                    return Type.FLOAT_TYPE;
                case Opcodes.DADD:
                case Opcodes.DSUB:
                case Opcodes.DMUL:
                case Opcodes.DDIV:
                    return Type.DOUBLE_TYPE;
                default:
                    return Type.INT_TYPE;
            }
        }

        private Type typeForLdc(Object cst) {
            if (cst instanceof Integer) {
                return Type.INT_TYPE;
            }
            if (cst instanceof Float) {
                return Type.FLOAT_TYPE;
            }
            if (cst instanceof Long) {
                return Type.LONG_TYPE;
            }
            if (cst instanceof Double) {
                return Type.DOUBLE_TYPE;
            }
            if (cst instanceof Type) {
                return Type.getObjectType("java/lang/Class");
            }
            return Type.getObjectType("java/lang/String");
        }

        private String mergeExpression(String left, String right) {
            if (String.valueOf(left).equals(String.valueOf(right))) {
                return left;
            }
            return "(" + left + " | " + right + ")";
        }

        private Type mergeType(Type left, Type right) {
            if (left == null) {
                return right;
            }
            if (right == null) {
                return left;
            }
            if (left.equals(right)) {
                return left;
            }
            if (left.getSort() == Type.OBJECT || left.getSort() == Type.ARRAY
                    || right.getSort() == Type.OBJECT || right.getSort() == Type.ARRAY) {
                return Type.getObjectType("java/lang/Object");
            }
            return left;
        }

        private Type defaultTypeForInstruction(AbstractInsnNode insnNode) {
            if (insnNode instanceof FieldInsnNode) {
                return Type.getType(((FieldInsnNode) insnNode).desc);
            }
            if (insnNode instanceof MethodInsnNode) {
                Type returnType = Type.getReturnType(((MethodInsnNode) insnNode).desc);
                return Type.VOID_TYPE.equals(returnType) ? null : returnType;
            }
            if (insnNode instanceof InvokeDynamicInsnNode) {
                Type returnType = Type.getReturnType(((InvokeDynamicInsnNode) insnNode).desc);
                return Type.VOID_TYPE.equals(returnType) ? null : returnType;
            }
            if (insnNode instanceof TypeInsnNode && insnNode.getOpcode() == Opcodes.ANEWARRAY) {
                return Type.getType("[L" + ((TypeInsnNode) insnNode).desc + ";");
            }
            return Type.getObjectType("java/lang/Object");
        }
    }
}
