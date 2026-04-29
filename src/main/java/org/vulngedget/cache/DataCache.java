package org.vulngedget.cache;

import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.reference.PathReference;
import org.vulngedget.util.VulnMethodInfo;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//此类做为数据的缓存类
public class DataCache {
    public static String packageInfo;
    public static HashMap<String, byte[]> classResources = new HashMap<>();
    public static List<MethodReference> allMethodReferenceList = new ArrayList<>();
    private static HashMap<MethodReference, List<MethodReference>> mapAllMethodReferenceList = new HashMap<MethodReference, List<MethodReference>>();
    public static ArrayList<ClassReference> allControllerClass = new ArrayList<>();
    public static HashMap<String, ClassReference> mapAllClass = new HashMap();
    private static HashMap<String, List<ClassReference>> mapAllInterface2Impl = new HashMap();
    public static HashMap<String, List<List<MethodReference>>> maybeVulnMapFlows = new HashMap<>();
    public static HashMap<String, List> classPath = new HashMap<>();
    public static ArrayList<PathReference> methodPath = new ArrayList<>();
    public static ArrayList<List<MethodReference>> sortMethods = new ArrayList<>();
    public static Map<String, Map<String, String>> customClassAnnotationSource = new HashMap<>();
    public static Map<String, Map<String, String>> customMethodAnnotationSource = new HashMap<>();
    public static Map<String, List<String>> customSourceMethods = new HashMap<>();
    public static String url = "http://localhost:8080";


    public static HashMap getMapAllMethodList() {
        //这里做了类型的转换,将list类的换成map
        if (mapAllMethodReferenceList.size() == 0) {
            for (MethodReference methodReference : allMethodReferenceList) {
                mapAllMethodReferenceList.put(methodReference, methodReference.calledMethodList);
            }
        }
        return mapAllMethodReferenceList;
    }

    public static HashMap<String, List<ClassReference>> getMapAllInterface2Impl() {
        if (mapAllInterface2Impl.size() == 0) {
            ArrayList<String> interfaces = new ArrayList<>();
            ArrayList<ClassReference> interfaceImpl = new ArrayList<>();
            for (String className : mapAllClass.keySet()) {
                ClassReference classReference = mapAllClass.get(className);
                if (classReference.isInterface) {
                    interfaces.add(className);
                } else if (classReference.interfacesList.size() != 0) {
                    interfaceImpl.add(classReference);
                }
            }
            for (String anInterface : interfaces) {
                ArrayList implList = new ArrayList();
                for (ClassReference classReference : interfaceImpl) {
                    for (String i : classReference.interfacesList) {
                        if (anInterface.equals(i)) {
                            if (anInterface.equals(i)) {
                                implList.add(classReference);
                            }
                        }
                    }
                }
                mapAllInterface2Impl.put(anInterface, implList);
            }
        }
        return mapAllInterface2Impl;
    }


    //如果一个接口方法被多个实现类实现,则返回多个
    public static List<MethodReference> getInterfaceImpl(MethodReference methodReference) {
        if (!methodReference.className.contains(packageInfo))return null;
        ArrayList<MethodReference> interfaceImplList = new ArrayList<>();
        List<ClassReference> classReferences = getMapAllInterface2Impl().get(methodReference.className);

        if (classReferences == null || classReferences.size() == 0) {
            return null;
        }
        for (ClassReference classReference : classReferences) {
            for (MethodReference reference : classReference.methodList) {
                if (reference.methodName.equals(methodReference.methodName) && reference.desc.equals(methodReference.desc)) {
                    interfaceImplList.add(reference);
                }
            }
        }
        return interfaceImplList;
    }

    //读取自定义的入口配置, 要么是注解, 要么是父子类情况,

    public static void initCustomSource() {
        try (InputStream in = DataCache.class.getResourceAsStream("/source.yaml")) {
            Yaml yaml = new Yaml();
            Map<String, Map<String, Object>> data = yaml.load(in);
            for (String s : data.keySet()) {
                if (s.equals("Annotation")) {
                    Map<String, Object> map = data.get(s);
                    String classAnnotation = (String) map.get("classAnnotation");
                    List<Map<String, String>> attributes = (List) map.get("classAttributes");
                    for (Map<String, String> attribute : attributes) {
                        String attr = attribute.get("attribute");
                        String value = attribute.get("value");
                        HashMap<String, String> attr2value = new HashMap<>();
                        attr2value.put(attr, value);
                        customClassAnnotationSource.put(classAnnotation, attr2value);
                    }

                    String methodAnnotation = (String) map.get("methodAnnotation");
                    List<Map<String, String>> methodAttributes = (List) map.get("methodAttributes");
                    for (Map<String, String> attribute : methodAttributes) {
                        String attr = attribute.get("attribute");
                        String value = attribute.get("value");
                        HashMap<String, String> attr2value = new HashMap<>();
                        attr2value.put(attr, value);
                        customMethodAnnotationSource.put(methodAnnotation, attr2value);
                    }

                }
                else {
                    Map<String, Object> map = data.get(s);
                    String className = (String) map.get("className");
                    List<Map<String, String>> methods = (List<Map<String, String>>) map.get("methods");
                    if (className == null || methods == null) {
                        continue;
                    }
                    ArrayList<String> methodSignatures = new ArrayList<>();
                    for (Map<String, String> method : methods) {
                        String methodName = method.get("methodName");
                        String desc = method.get("desc");
                        if (methodName == null || desc == null) {
                            continue;
                        }
                        methodSignatures.add(methodName + "#" + desc);
                    }
                    if (!methodSignatures.isEmpty()) {
                        customSourceMethods.put(className, methodSignatures);
                    }

                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getPackageInfo() {
        return packageInfo;
    }

    public static void setPackageInfo(String packageInfo) {
        DataCache.packageInfo = packageInfo;
    }

    public static boolean isJavaClass(String className){
        if (className.contains("java/")){
            return true;
        }
        return false;
    }

    public static boolean isCustomSourceMethod(String className, String methodName, String desc) {
        List<String> methodSignatures = customSourceMethods.get(className);
        if (methodSignatures == null || methodSignatures.isEmpty()) {
            return false;
        }
        String methodSig = methodName + "#" + desc;
        return methodSignatures.contains(methodSig);
    }


    public static void main(String[] args) {
        initCustomSource();
    }


}
