package org.vulngedget;

import freemarker.template.TemplateException;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.vulngedget.cache.DataCache;
import org.vulngedget.flows.FlowsClassVisitor;
import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.util.TemplateUtil;
import org.vulngedget.visitor.SpringBootAllClassVisitor;
import org.vulngedget.visitor.SpringBootControllerClassVisitor;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

import static org.vulngedget.cache.DataCache.*;
import static org.vulngedget.util.VulnMethodInfo.*;

public class SpringbootMain {

    private static final int MAX_PATH_DEPTH = Integer.getInteger("vulngadget.maxDepth", 60);
    private static final int MAX_PATHS_PER_ENTRY = Integer.getInteger("vulngadget.maxPathsPerEntry", 2000);

    public static void main(String[] args) throws IOException, TemplateException {
        String packagePrefix = args.length > 0 ? args[0] : "nds/ehcache";
        String jarDirPath = args.length > 1
                ? args[1]
                : "C:\\Users\\Administrator\\Desktop\\VulnGadget\\src\\main\\resources\\scanJar\\";

        DataCache.setPackageInfo(packagePrefix);
        scanJarDirectory(new File(jarDirPath));

        for (ClassReference controllerClass : allControllerClass) {
            byte[] bytes = classResources.get(controllerClass.className);
            if (bytes == null) {
                continue;
            }
            ClassReader classReader = new ClassReader(bytes);
            SpringBootControllerClassVisitor controllerClassVisitor = new SpringBootControllerClassVisitor();
            classReader.accept(controllerClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        }

        Map<MethodReference, List<MethodReference>> methodGraph = getMapAllMethodList();
        for (ClassReference controllerClass : allControllerClass) {
            for (MethodReference methodReference : controllerClass.methodList) {
                if (!methodReference.isControllerMethod) {
                    continue;
                }
                ArrayList<List<MethodReference>> entryPaths = collectMethodPaths(methodGraph, methodReference);
                sortMethods.addAll(entryPaths);
            }
        }

        init(false);
        for (List<MethodReference> sortMethod : sortMethods) {
            checkRCEFlows(sortMethod);
            checkDeserializationFlows(sortMethod);
            checkSSRFFlows(sortMethod);
            checkXXEFlows(sortMethod);
            checkFileVulnFlows(sortMethod);
            checkSqlFlows(sortMethod);
        }
        countVulnFlow();

        TemplateUtil.getJsonResult();
        TemplateUtil.getWebPath();
        TemplateUtil.getAllFlow();
        TemplateUtil.getCompleteFlowText();
        TemplateUtil.getCompleteFlowJson();
        System.out.println(allControllerClass.size());
        // flows(false);
    }

    private static void scanJarDirectory(File dirPath) throws IOException {
        File[] files = dirPath.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (!file.isFile()) {
                continue;
            }
            try (JarFile jarFile = new JarFile(file)) {
                scanJarFile(jarFile);
            }
        }
    }

    private static void scanJarFile(JarFile jarFile) throws IOException {
        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry jarEntry = entries.nextElement();
            if (jarEntry.isDirectory()) {
                continue;
            }
            try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
                if (jarEntry.getName().endsWith(".class")) {
                    visitClass(IOUtils.toByteArray(inputStream));
                } else if (jarEntry.getName().endsWith(".jar")) {
                    readNestedJarFile(IOUtils.toByteArray(inputStream));
                }
            }
        }
    }

    private static void visitClass(byte[] byteArray) {
        try {
            ClassReader classReader = new ClassReader(byteArray);
            SpringBootAllClassVisitor allClassVisitor = new SpringBootAllClassVisitor(byteArray);
            classReader.accept(allClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (IllegalArgumentException ignored) {
            // Skip invalid classes instead of breaking the whole scan.
        }
    }

    private static void readNestedJarFile(byte[] jarBytes) throws IOException {
        try (JarInputStream jarInputStream = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
            JarEntry jarEntry = jarInputStream.getNextJarEntry();
            while (jarEntry != null) {
                if (!jarEntry.isDirectory() && jarEntry.getName().endsWith(".class")) {
                    visitClass(IOUtils.toByteArray(jarInputStream));
                } else if (!jarEntry.isDirectory() && jarEntry.getName().endsWith(".jar")) {
                    readNestedJarFile(IOUtils.toByteArray(jarInputStream));
                }
                jarEntry = jarInputStream.getNextJarEntry();
            }
        }
    }

    public static ArrayList<List<MethodReference>> collectMethodPaths(Map<MethodReference, List<MethodReference>> methodGraph,
                                                                       MethodReference entryMethod) {
        ArrayList<List<MethodReference>> result = new ArrayList<>();
        LinkedList<MethodReference> currentPath = new LinkedList<>();
        HashSet<MethodReference> currentPathSet = new HashSet<>();
        HashSet<String> pathKeySet = new HashSet<>();

        dfsCollectPaths(methodGraph, entryMethod, currentPath, currentPathSet, result, pathKeySet, 0);
        return result;
    }

    private static void dfsCollectPaths(Map<MethodReference, List<MethodReference>> methodGraph,
                                        MethodReference current,
                                        LinkedList<MethodReference> currentPath,
                                        HashSet<MethodReference> currentPathSet,
                                        ArrayList<List<MethodReference>> result,
                                        HashSet<String> pathKeySet,
                                        int depth) {
        if (depth > MAX_PATH_DEPTH || result.size() >= MAX_PATHS_PER_ENTRY) {
            return;
        }

        currentPath.add(current);
        currentPathSet.add(current);

        List<MethodReference> nextMethods = resolveNextMethods(methodGraph, current);
        if (nextMethods.isEmpty()) {
            addPathIfAbsent(result, pathKeySet, currentPath);
        } else {
            boolean hasForward = false;
            for (MethodReference nextMethod : nextMethods) {
                if (currentPathSet.contains(nextMethod)) {
                    continue;
                }
                hasForward = true;
                dfsCollectPaths(methodGraph, nextMethod, currentPath, currentPathSet, result, pathKeySet, depth + 1);
                if (result.size() >= MAX_PATHS_PER_ENTRY) {
                    break;
                }
            }
            if (!hasForward) {
                addPathIfAbsent(result, pathKeySet, currentPath);
            }
        }

        currentPath.removeLast();
        currentPathSet.remove(current);
    }

    private static void addPathIfAbsent(ArrayList<List<MethodReference>> result,
                                        HashSet<String> pathKeySet,
                                        LinkedList<MethodReference> currentPath) {
        StringBuilder keyBuilder = new StringBuilder();
        for (MethodReference method : currentPath) {
            keyBuilder.append(method.className).append('#')
                    .append(method.methodName).append('#')
                    .append(method.desc).append('|');
        }
        String key = keyBuilder.toString();
        if (!pathKeySet.add(key)) {
            return;
        }
        result.add(new ArrayList<>(currentPath));
    }

    private static List<MethodReference> resolveNextMethods(Map<MethodReference, List<MethodReference>> methodGraph,
                                                             MethodReference methodReference) {
        LinkedHashSet<MethodReference> mergedMethods = new LinkedHashSet<>();

        List<MethodReference> directMethods = methodGraph.get(methodReference);
        if (directMethods != null && !directMethods.isEmpty()) {
            mergedMethods.addAll(directMethods);
        }

        List<MethodReference> parentMethods = getParentCalledMethods(methodReference);
        if (parentMethods != null) {
            mergedMethods.addAll(parentMethods);
        }

        List<MethodReference> implMethods = getInterfaceImpl(methodReference);
        if (implMethods != null) {
            mergedMethods.addAll(implMethods);
        }

        if (mergedMethods.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<>(mergedMethods);
    }

    public static List<MethodReference> getParentCalledMethods(MethodReference methodReference) {
        String searchClassName = methodReference.className;
        while (searchClassName != null && searchClassName.contains(packageInfo)) {
            ClassReference childClass = mapAllClass.get(searchClassName);
            if (childClass == null || "java/lang/Object".equals(childClass.className)) {
                return null;
            }

            ClassReference parentClass = mapAllClass.get(childClass.superClassName);
            if (parentClass == null || "java/lang/Object".equals(parentClass.className)) {
                return null;
            }

            for (MethodReference reference : parentClass.methodList) {
                if (reference.methodName.equals(methodReference.methodName)
                        && reference.desc.equals(methodReference.desc)) {
                    return reference.calledMethodList;
                }
            }
            searchClassName = childClass.superClassName;
        }
        return null;
    }

    public static void flows(boolean b) {
        if (b) {
            for (ClassReference controllerClass : allControllerClass) {
                byte[] bytes = classResources.get(controllerClass.className);
                if (bytes == null) {
                    continue;
                }
                ClassReader classReader = new ClassReader(bytes);
                FlowsClassVisitor controllerClassVisitor = new FlowsClassVisitor();
                classReader.accept(controllerClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            }
        }
    }
}

