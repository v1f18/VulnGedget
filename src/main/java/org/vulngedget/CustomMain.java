package org.vulngedget;

import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.vulngedget.cache.DataCache;
import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.util.TemplateUtil;
import org.vulngedget.visitor.CustomAllClassVisitor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

import static org.vulngedget.cache.DataCache.*;
import static org.vulngedget.util.VulnMethodInfo.*;

//姝ょ被鏄敤鏉ュ鐞嗗綋娴嬭瘯绯荤粺涓嶄负springboot锛宻ource鏄嚜瀹氫箟绫诲瀷鐨勬椂鍊?
public class CustomMain {
    public static void main(String[] args) throws IOException {
        String packagePrefix = args.length > 0 ? args[0] : "com/siro";
        String jarDirPath = args.length > 1
                ? args[1]
                : "C:\\Users\\Administrator\\Desktop\\VulnGadget\\src\\main\\resources\\scanJar";

        DataCache.setPackageInfo(packagePrefix);
        initCustomSource();
        scanJarDirectory(new File(jarDirPath));

        Map<MethodReference, List<MethodReference>> methodGraph = getMapAllMethodList();
        for (ClassReference controllerClass : allControllerClass) {
            for (MethodReference methodReference : controllerClass.methodList) {
                if (!methodReference.isControllerMethod) {
                    continue;
                }
                ArrayList<List<MethodReference>> entryPaths = SpringbootMain.collectMethodPaths(methodGraph, methodReference);
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
            CustomAllClassVisitor allClassVisitor = new CustomAllClassVisitor(byteArray);
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
}

