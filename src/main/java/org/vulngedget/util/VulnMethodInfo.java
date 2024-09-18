package org.vulngedget.util;

import org.vulngedget.reference.MethodReference;
import org.yaml.snakeyaml.Yaml;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import static org.vulngedget.cache.DataCache.maybeVulnMapFlows;

public class VulnMethodInfo {

    private static Map<String, List<String>> SSRFMethodInfo = new HashMap<>();
    private static Map<String, List<String>> RCEMethodInfo = new HashMap<>();
    private static Map<String, List<String>> DeserializationMethodInfo = new HashMap<>();
    private static Map<String, List<String>> XXEMethodInfo = new HashMap<>();
    private static Map<String, List<String>> FileVulnMethodInfo = new HashMap<>();
    private static Map<String, List<String>> SqlMethodInfo = new HashMap<>();
    private static Map<String, List<String>> OtherMethodInfo = new HashMap<>();

    public static ArrayList<List<MethodReference>> SSRFResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> RCEResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> DeserializationResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> XXEResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> FileVulnResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> SqlResult = new ArrayList<>();
    public static ArrayList<List<MethodReference>> OtherResult = new ArrayList<>();


    public static void init(boolean isOther) {
        try (InputStream in = VulnMethodInfo.class.getResourceAsStream("/methodInfo.yaml")) {
            Yaml yaml = new Yaml();
            Map<String, List<Map<String, Object>>> data = yaml.load(in);
            initSSRF(data,in);
            initRCE(data,in);
            initDeserialization(data,in);
            initXXE(data,in);
            initFileVuln(data,in);
            initSqlVuln(data,in);
            if (isOther){
            initOtherVuln(data,in);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initSSRF(Map<String, List<Map<String, Object>>> data, InputStream in) {

        List<Map<String, Object>> ssrf = data.get("SSRF");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            SSRFMethodInfo.put(className, vulns);
        }
    }

    private static void initRCE(Map<String, List<Map<String, Object>>> data,InputStream in){
        List<Map<String, Object>> ssrf = data.get("RCE");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            RCEMethodInfo.put(className, vulns);
        }
    }

    private static void initDeserialization(Map<String, List<Map<String, Object>>> data, InputStream in) {
        List<Map<String, Object>> ssrf = data.get("Deserialization");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            DeserializationMethodInfo.put(className, vulns);
        }
    }
    private static void initXXE(Map<String, List<Map<String, Object>>> data, InputStream in) {
        List<Map<String, Object>> ssrf = data.get("XXE");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            XXEMethodInfo.put(className, vulns);
        }
    }

    private static void initFileVuln(Map<String, List<Map<String, Object>>> data, InputStream in) {
        List<Map<String, Object>> ssrf = data.get("FileVuln");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            FileVulnMethodInfo.put(className, vulns);
        }
    }
    private static void initSqlVuln(Map<String, List<Map<String, Object>>> data, InputStream in) {
        List<Map<String, Object>> ssrf = data.get("Sql");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            SqlMethodInfo.put(className, vulns);
        }
    }

    private static void initOtherVuln(Map<String, List<Map<String, Object>>> data, InputStream in) {
        List<Map<String, Object>> ssrf = data.get("Other");
        for (Map<String, Object> infos : ssrf) {
            String className = (String) infos.get("className");
            ArrayList<Map> methodList = (ArrayList) infos.get("methods");
            ArrayList<String> vulns = new ArrayList<>();
            for (Map method : methodList) {
                vulns.add(method.get("methodName") + "#" + method.get("desc"));
            }
            OtherMethodInfo.put(className, vulns);
        }
    }


    public static void checkOtherFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = OtherMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        OtherResult.add(l);
                    }
                }
            }
        }
    }



    public static void checkSqlFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = SqlMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        SqlResult.add(l);
                    }
                }
            }
        }
    }


    public static void checkFileVulnFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = FileVulnMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        FileVulnResult.add(l);
                    }
                }
            }
        }
    }



    public static void checkXXEFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = XXEMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        XXEResult.add(l);
                    }
                }
            }
        }
    }


    public static void checkSSRFFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = SSRFMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        SSRFResult.add(l);
                    }
                }
            }
        }
    }


    public static void checkRCEFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = RCEMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        RCEResult.add(l);
                    }
                }
            }
        }
    }
    public static void checkDeserializationFlows(List<MethodReference> methodReferenceList) {
        int num = 0;
        for (MethodReference methodReference : methodReferenceList) {
            List<String> vulnList = DeserializationMethodInfo.get(methodReference.className);
            if (vulnList != null) {
                for (String s : vulnList) {
                    String[] split = s.split("#");
                    if (split[0].contains(methodReference.methodName) && split[1].contains(methodReference.desc)) {
                        num = methodReferenceList.indexOf(methodReference);
                        List<MethodReference> l = methodReferenceList.subList(0, num + 1);
                        DeserializationResult.add(l);
                    }
                }
            }
        }
    }

    public static void countVulnFlow(){
        if (!RCEResult.isEmpty()){
            maybeVulnMapFlows.put("RCE",RCEResult);
        }
        if (!SSRFResult.isEmpty()){
            maybeVulnMapFlows.put("SSRF",SSRFResult);
        }
        if (!DeserializationResult.isEmpty()){
            maybeVulnMapFlows.put("Deserialization",DeserializationResult);
        }
        if (!XXEResult.isEmpty()){
            maybeVulnMapFlows.put("XXE",XXEResult);
        }
        if (!FileVulnResult.isEmpty()){
            maybeVulnMapFlows.put("File",FileVulnResult);
        }
        if (!SqlResult.isEmpty()){
            maybeVulnMapFlows.put("Sql",SqlResult);
        }
        if (!OtherResult.isEmpty()){
            maybeVulnMapFlows.put("Other",SqlResult);
        }
    }



    public static void main(String[] args) {
        init();
    }
}
