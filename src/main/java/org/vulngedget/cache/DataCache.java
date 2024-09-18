package org.vulngedget.cache;

import org.vulngedget.reference.ClassReference;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.reference.PathReference;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DataCache {
    public static HashMap<String,byte[]> classResources = new HashMap<>();
    public static List<MethodReference> allMethodReferenceList = new ArrayList<>();
    private static HashMap<MethodReference, List<MethodReference>> mapAllMethodReferenceList = new HashMap<MethodReference, List<MethodReference>>();
    public static ArrayList<ClassReference> allControllerClass = new ArrayList<>();
    public static HashMap<String, ClassReference> mapAllClass = new HashMap();
    private static HashMap<String, List<ClassReference>> mapAllInterface2Impl = new HashMap();
    public static HashMap<String,List<List<MethodReference>>> maybeVulnMapFlows = new HashMap<>();
    public static HashMap<String,List> classPath = new HashMap<>();
    public static ArrayList<PathReference> methodPath = new ArrayList<>();
    public static ArrayList<List<MethodReference>> sortMethods = new ArrayList<>();

    public static HashMap getMapAllMethodList(){
        if (mapAllMethodReferenceList.size() == 0){
            for (MethodReference methodReference : allMethodReferenceList) {
                mapAllMethodReferenceList.put(methodReference,methodReference.calledMethodList);
            }
        }
        return mapAllMethodReferenceList;
    }

    public static HashMap<String,List<ClassReference>> getMapAllInterface2Impl(){
        if (mapAllInterface2Impl.size() == 0){
            ArrayList<String> interfaces = new ArrayList<>();
            ArrayList<ClassReference> interfaceImpl = new ArrayList<>();
            for (String className : mapAllClass.keySet()) {
                ClassReference classReference = mapAllClass.get(className);
                if (classReference.isInterface){
                    interfaces.add(className);
                } else if (classReference.interfacesList.size() != 0) {
                    interfaceImpl.add(classReference);
                }
            }
            for (String anInterface : interfaces) {
                ArrayList implList = new ArrayList();
                for (ClassReference classReference : interfaceImpl) {
                    for (String i : classReference.interfacesList) {
                        if (anInterface.equals(i)){
                            if (anInterface.equals(i)){
                                implList.add(classReference);
                            }
                        }
                    }
                }
                mapAllInterface2Impl.put(anInterface,implList);
            }
        }
        return mapAllInterface2Impl;
    }


    //如果一个接口方法被多个实现类实现,则返回多个
    public static List<MethodReference> getInterfaceImpl(MethodReference methodReference){
        ArrayList<MethodReference> interfaceImplList = new ArrayList<>();
        List<ClassReference> classReferences = getMapAllInterface2Impl().get(methodReference.className);
        if (classReferences == null || classReferences.size() == 0){
            return null;
        }
        for (ClassReference classReference : classReferences) {
            for (MethodReference reference : classReference.methodList) {
                if (reference.methodName.equals(methodReference.methodName) && reference.desc.equals(methodReference.desc)){
                    interfaceImplList.add(reference);
                }
            }
        }
        return interfaceImplList;
    }





}
