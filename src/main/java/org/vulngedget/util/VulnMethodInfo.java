package org.vulngedget.util;

import org.vulngedget.reference.MethodReference;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import static org.vulngedget.cache.DataCache.maybeVulnMapFlows;

public class VulnMethodInfo {

    private static final Map<String, Set<String>> SSRFMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> RCEMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> DeserializationMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> XXEMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> FileVulnMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> SqlMethodInfo = new HashMap<>();
    private static final Map<String, Set<String>> OtherMethodInfo = new HashMap<>();

    public static final ArrayList<List<MethodReference>> SSRFResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> RCEResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> DeserializationResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> XXEResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> FileVulnResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> SqlResult = new ArrayList<>();
    public static final ArrayList<List<MethodReference>> OtherResult = new ArrayList<>();

    private static final Set<String> ssrfPathKeySet = new HashSet<>();
    private static final Set<String> rcePathKeySet = new HashSet<>();
    private static final Set<String> deserializationPathKeySet = new HashSet<>();
    private static final Set<String> xxePathKeySet = new HashSet<>();
    private static final Set<String> filePathKeySet = new HashSet<>();
    private static final Set<String> sqlPathKeySet = new HashSet<>();
    private static final Set<String> otherPathKeySet = new HashSet<>();

    //璇诲彇婕忔礊閰嶇疆鏂囦欢锛屽嵆sinks
    public static void init(boolean isOther) {
        clearResults();
        clearMethodInfo();
        try (InputStream in = VulnMethodInfo.class.getResourceAsStream("/methodInfo.yaml")) {
            Yaml yaml = new Yaml();
            Map<String, List<Map<String, Object>>> data = yaml.load(in);
            initByType(data, "SSRF", SSRFMethodInfo);
            initByType(data, "RCE", RCEMethodInfo);
            initByType(data, "Deserialization", DeserializationMethodInfo);
            initByType(data, "XXE", XXEMethodInfo);
            initByType(data, "FileVuln", FileVulnMethodInfo);
            initByType(data, "Sql", SqlMethodInfo);
            if (isOther) {
                initByType(data, "Other", OtherMethodInfo);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initByType(Map<String, List<Map<String, Object>>> data,
                                   String type,
                                   Map<String, Set<String>> targetMap) {
        List<Map<String, Object>> vulnInfos = data.get(type);
        if (vulnInfos == null) {
            return;
        }
        for (Map<String, Object> infos : vulnInfos) {
            String className = (String) infos.get("className");
            List<Map<String, String>> methodList = (List<Map<String, String>>) infos.get("methods");
            if (className == null || methodList == null) {
                continue;
            }
            Set<String> vulns = new HashSet<>();
            for (Map<String, String> method : methodList) {
                String methodName = method.get("methodName");
                String desc = method.get("desc");
                if (methodName == null || desc == null) {
                    continue;
                }
                vulns.add(methodName + "#" + desc);
            }
            targetMap.put(className, vulns);
        }
    }

    public static void checkOtherFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, OtherMethodInfo, OtherResult, otherPathKeySet);
    }

    public static void checkSqlFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, SqlMethodInfo, SqlResult, sqlPathKeySet);
    }

    public static void checkFileVulnFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, FileVulnMethodInfo, FileVulnResult, filePathKeySet);
    }

    public static void checkXXEFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, XXEMethodInfo, XXEResult, xxePathKeySet);
    }

    public static void checkSSRFFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, SSRFMethodInfo, SSRFResult, ssrfPathKeySet);
    }

    public static void checkRCEFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, RCEMethodInfo, RCEResult, rcePathKeySet);
    }

    public static void checkDeserializationFlows(List<MethodReference> methodReferenceList) {
        checkSinkFlows(methodReferenceList, DeserializationMethodInfo, DeserializationResult, deserializationPathKeySet);
    }

    private static void checkSinkFlows(List<MethodReference> methodReferenceList,
                                       Map<String, Set<String>> sinkMap,
                                       List<List<MethodReference>> result,
                                       Set<String> pathKeySet) {
        for (int i = 0; i < methodReferenceList.size(); i++) {
            MethodReference methodReference = methodReferenceList.get(i);
            Set<String> vulnList = sinkMap.get(methodReference.className);
            if (vulnList == null || vulnList.isEmpty()) {
                continue;
            }

            String sinkSig = methodReference.methodName + "#" + methodReference.desc;
            if (!vulnList.contains(sinkSig)) {
                continue;
            }

            List<MethodReference> subPath = new ArrayList<>(methodReferenceList.subList(0, i + 1));
            String pathKey = buildPathKey(subPath);
            if (!pathKeySet.add(pathKey)) {
                continue;
            }
            result.add(subPath);
        }
    }

    private static String buildPathKey(List<MethodReference> methods) {
        StringBuilder keyBuilder = new StringBuilder();
        for (MethodReference method : methods) {
            keyBuilder.append(method.className).append('#')
                    .append(method.methodName).append('#')
                    .append(method.desc).append('|');
        }
        return keyBuilder.toString();
    }

    private static void clearMethodInfo() {
        SSRFMethodInfo.clear();
        RCEMethodInfo.clear();
        DeserializationMethodInfo.clear();
        XXEMethodInfo.clear();
        FileVulnMethodInfo.clear();
        SqlMethodInfo.clear();
        OtherMethodInfo.clear();
    }

    private static void clearResults() {
        SSRFResult.clear();
        RCEResult.clear();
        DeserializationResult.clear();
        XXEResult.clear();
        FileVulnResult.clear();
        SqlResult.clear();
        OtherResult.clear();

        ssrfPathKeySet.clear();
        rcePathKeySet.clear();
        deserializationPathKeySet.clear();
        xxePathKeySet.clear();
        filePathKeySet.clear();
        sqlPathKeySet.clear();
        otherPathKeySet.clear();
    }

    public static void countVulnFlow() {
        maybeVulnMapFlows.clear();
        if (!RCEResult.isEmpty()) {
            maybeVulnMapFlows.put("RCE", RCEResult);
        }
        if (!SSRFResult.isEmpty()) {
            maybeVulnMapFlows.put("SSRF", SSRFResult);
        }
        if (!DeserializationResult.isEmpty()) {
            maybeVulnMapFlows.put("Deserialization", DeserializationResult);
        }
        if (!XXEResult.isEmpty()) {
            maybeVulnMapFlows.put("XXE", XXEResult);
        }
        if (!FileVulnResult.isEmpty()) {
            maybeVulnMapFlows.put("File", FileVulnResult);
        }
        if (!SqlResult.isEmpty()) {
            maybeVulnMapFlows.put("Sql", SqlResult);
        }
        if (!OtherResult.isEmpty()) {
            maybeVulnMapFlows.put("Other", OtherResult);
        }
    }

    public static void main(String[] args) {
        init(false);
    }
}

