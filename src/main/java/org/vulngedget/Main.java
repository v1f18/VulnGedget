package org.vulngedget;

import freemarker.template.TemplateException;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.util.TemplateUtil;
import org.vulngedget.visitor.AllClassVisitor;
import org.vulngedget.visitor.ControllerClassVisitor;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

import static org.vulngedget.cache.DataCache.*;
import static org.vulngedget.util.VulnMethodInfo.*;


public class Main {
    public static void main(String[] args) throws IOException, TemplateException {
        String jarDirPath = "C:\\Users\\Administrator\\Desktop\\VulnGedget\\src\\main\\resources\\scanJar";
        File dirPath = new File(jarDirPath);
        try {
            for (File file : dirPath.listFiles()) {
                if (file.isFile()) {
                    JarFile jarFile = new JarFile(file);
                    Enumeration<JarEntry> entries = jarFile.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry jarEntry = entries.nextElement();
                        if (!jarEntry.isDirectory() && jarEntry.getName().endsWith(".class")) {
                            InputStream inputStream = jarFile.getInputStream(jarEntry);
                            byte[] byteArray = IOUtils.toByteArray(inputStream);
                            ClassReader classReader = new ClassReader(byteArray);
                            AllClassVisitor allClassVisitor = new AllClassVisitor(byteArray);
                            classReader.accept(allClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                        }
                    }
                }
            }
        } catch (IllegalArgumentException e) {

        }
        //对controller类进行路径处理
        for (ClassReference controllerClass : allControllerClass) {
            byte[] bytes = classResources.get(controllerClass.className);
            ClassReader classReader = new ClassReader(bytes);
            ControllerClassVisitor controllerClassVisitor = new ControllerClassVisitor();
            classReader.accept(controllerClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        }

        for (ClassReference controllerClass : allControllerClass) {
            for (MethodReference methodReference : controllerClass.methodList) {
                if (methodReference.isControllerMethod) {
                    ArrayList<MethodReference> list = new ArrayList<>();
                    sortMethodCalls(getMapAllMethodList(), list, methodReference);
                    sortMethods.add(list);
                }
            }
        }

        //对接口方法的调用流进行漏洞方法判断
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
    }

    //在java中,子类调用父类的方法时,首先会从子类开始找,所以在class中,保存的是子类的方法,如果子类没有,jvm会向上找,所以这里需要模拟一下jvm的操作
    //需要写一个如果在所有方法中没有这个方法,那么需要去父类里面找一下
    public static void sortMethodCalls(Map<MethodReference, List<MethodReference>> mapAllMethodReference, ArrayList<MethodReference> sort, MethodReference methodReference) {
        if (!sort.contains(methodReference)) {
            sort.add(methodReference);
        }
        List<MethodReference> methodReferences = mapAllMethodReference.get(methodReference);
        if (methodReferences == null || methodReferences.size() == 0) {
            methodReferences = getParent(methodReference);
            if (methodReferences == null || methodReferences.size() == 0){
                methodReferences = getInterfaceImpl(methodReference);
                if (methodReferences == null || methodReferences.size() == 0){
                    return;
                }
            }
        }
        try{
            for (MethodReference reference : methodReferences) {
                sortMethodCalls(mapAllMethodReference, sort, reference);
            }
        }catch (StackOverflowError e){
            System.out.println(e);
        }
    }

    //向父类来找
    public static List<MethodReference> getParent(MethodReference methodReference) {
        //往上找父类
        ClassReference classReference1 = mapAllClass.get(methodReference.className);
        if (classReference1 != null && !classReference1.className.equals("java/lang/Object")){
            ClassReference classReference = mapAllClass.get(classReference1.superClassName);
            if (classReference == null || classReference.className.equals("java/lang/Object")){
                return null;
            }

            for (MethodReference reference : classReference.methodList) {
                if (reference.methodName.equals(methodReference.methodName) && reference.desc.equals(methodReference.desc)){
                    return reference.calledMethodList;
                }
            }
            methodReference.className = classReference1.superClassName;
            return getParent(methodReference);
        }

        return null;
    }

    private static void readNestedJarFile(InputStream inputStream) throws IOException {
        JarInputStream jarInputStream = new JarInputStream(inputStream);
        JarEntry jarEntry = jarInputStream.getNextJarEntry();
        while (jarEntry != null) {
            if (!jarEntry.isDirectory() && jarEntry.getName().endsWith(".class")) {
                byte[] byteArray = IOUtils.toByteArray(jarInputStream);
                ClassReader classReader = new ClassReader(byteArray);
                AllClassVisitor allClassVisitor = new AllClassVisitor(byteArray);
                classReader.accept(allClassVisitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            } else if (!jarEntry.isDirectory() && jarEntry.getName().endsWith(".jar")) {
                readNestedJarFile(jarInputStream);
            }

            jarEntry = jarInputStream.getNextJarEntry(); // 读取下一个JAR包条目
        }


    }


}