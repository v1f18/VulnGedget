package org.vulngedget.util;

import com.alibaba.fastjson.JSON;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.Type;
import org.vulngedget.reference.InvocationDetail;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.reference.PathReference;
import org.vulngedget.reference.VulnerabilityFlowDetail;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.vulngedget.cache.DataCache.*;

public class TemplateUtil {
    public static void getHtml() throws IOException, TemplateException {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_28);
        configuration.setClassForTemplateLoading(TemplateUtil.class,"/templates");
        Template template = configuration.getTemplate("test.ftl");
        StringWriter stringWriter = new StringWriter();
        template.process(maybeVulnMapFlows,stringWriter);
        FileOutputStream fileOutputStream = new FileOutputStream(new File("out2.html"));
        IOUtils.write(stringWriter.toString(),fileOutputStream);
    }

    public static void getJsonResult() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("result.txt");
        for (String v : maybeVulnMapFlows.keySet()) {
            IOUtils.write(v+"\n",fileOutputStream);
            for (List<MethodReference> methodReferences : maybeVulnMapFlows.get(v)) {
                IOUtils.write("URL:  "+getPath(methodReferences.get(0).className, methodReferences.get(0).methodName)+"\n",fileOutputStream);
                IOUtils.write("QueryString: ",fileOutputStream);
                for (Type argumentType : Type.getType(methodReferences.get(0).getDesc()).getArgumentTypes()) {
                    IOUtils.write(argumentType.getDescriptor(),fileOutputStream);
                }
                IOUtils.write("\n",fileOutputStream);
                IOUtils.write("Call Method Args: \n",fileOutputStream);

                for (MethodReference methodReference : methodReferences) {
                    if ((methodReferences.indexOf(methodReference) != methodReferences.size()-1) ){
                        if (!methodReference.className.contains(packageInfo)){
                            continue;
                        }
                    }
                    IOUtils.write(methodReference.className+"#"+methodReference.methodName+"\n",fileOutputStream);
                }
                IOUtils.write("---------------------------\n",fileOutputStream);
            }
        }
    }

    public static String getSpace(int num){
        String s = " ";
        for (int i = 0; i < num; i++) {
            s = s+" ";
        }
        return s;
    }

    public static String getPath(String className, String methodName){
        List classList = classPath.get(className);
        String p1 = "";
        if ( classList != null && classList.size()!=0){
            p1 = (String) classList.get(0);
        }
        String p2 = "";
        for (PathReference pathReference : methodPath) {
            if (methodName.equals(pathReference.methodName) && className.equals(pathReference.className)){
                if (pathReference.paths != null && pathReference.paths.size()!=0){
                p2 = (String) pathReference.paths.get(0);
                }
                break;
            }
        }
        if (p1.startsWith("/")){
            if (p2.startsWith("/")){
                return url + p1 + p2;
            }
        }
        return url + "/" + p1 + p2;

    }

    public static void getWebPath() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("webpath.txt");
        for (PathReference pathReference : methodPath) {
            List list = classPath.get(pathReference.className);
            if (list.size()!=0){
                String p1 = (String) list.get(0);
                p1 = p1.replace("**", "");
                if (pathReference.paths.size()!=0){
                for (Object path : pathReference.paths) {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+p1+path+"\n",fileOutputStream);
                }
                }else {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+p1+"\n",fileOutputStream);

                }
            }else {
                for (Object path : pathReference.paths) {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+path+"\n",fileOutputStream);

                }
            }
        }
    }


    public static void getAllFlow() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("allFlow.txt");

        for (List<MethodReference> sortMethod : sortMethods) {
            IOUtils.write("URL:  "+getPath(sortMethod.get(0).className, sortMethod.get(0).methodName)+"\n",fileOutputStream);
            IOUtils.write("QueryString: ",fileOutputStream);
            for (Type argumentType : Type.getType(sortMethod.get(0).getDesc()).getArgumentTypes()) {
                IOUtils.write(argumentType.getDescriptor(),fileOutputStream);
            }

            IOUtils.write("\n",fileOutputStream);
            IOUtils.write("Call Method Args: \n",fileOutputStream);
            for (MethodReference methodReference : sortMethod) {
                IOUtils.write(methodReference.className+"#"+methodReference.methodName+"\n",fileOutputStream);
            }

            IOUtils.write("---------------------------"+'\n',fileOutputStream);
        }
    }

    public static void getCompleteFlowText() throws IOException {
        Map<String, List<VulnerabilityFlowDetail>> flowDetails = FlowDetailBuilder.buildAllVulnerabilityFlowDetails();
        FileOutputStream fileOutputStream = new FileOutputStream("completeFlow.txt");
        for (String vulnType : flowDetails.keySet()) {
            for (VulnerabilityFlowDetail flowDetail : flowDetails.get(vulnType)) {
                IOUtils.write("VulnType: " + flowDetail.vulnType + "\n", fileOutputStream);
                IOUtils.write("URL: " + flowDetail.url + "\n", fileOutputStream);
                IOUtils.write("Entry: " + FlowDetailBuilder.formatMethodSignature(
                        flowDetail.entryClassName,
                        flowDetail.entryMethodName,
                        flowDetail.entryDesc) + "\n", fileOutputStream);
                IOUtils.write("EntryParameters: " + flowDetail.entryParameters + "\n", fileOutputStream);
                IOUtils.write("Invocations:\n", fileOutputStream);
                for (int i = 0; i < flowDetail.invocations.size(); i++) {
                    InvocationDetail invocationDetail = flowDetail.invocations.get(i);
                    IOUtils.write((i + 1) + ". "
                            + FlowDetailBuilder.formatMethodSignature(
                            invocationDetail.callerClassName,
                            invocationDetail.callerMethodName,
                            invocationDetail.callerDesc)
                            + " -> "
                            + FlowDetailBuilder.formatMethodSignature(
                            invocationDetail.calleeClassName,
                            invocationDetail.calleeMethodName,
                            invocationDetail.calleeDesc)
                            + "\n", fileOutputStream);
                    IOUtils.write("   receiver: " + invocationDetail.receiver + "\n", fileOutputStream);
                    IOUtils.write("   args: " + invocationDetail.arguments + "\n", fileOutputStream);
                    IOUtils.write("   line: " + invocationDetail.lineNumber + "\n", fileOutputStream);
                    IOUtils.write("   candidates: " + invocationDetail.candidateCount + "\n", fileOutputStream);
                }
                IOUtils.write("---------------------------\n", fileOutputStream);
            }
        }
    }

    public static void getCompleteFlowJson() throws IOException {
        Map<String, List<VulnerabilityFlowDetail>> flowDetails = FlowDetailBuilder.buildAllVulnerabilityFlowDetails();
        FileOutputStream fileOutputStream = new FileOutputStream("completeFlow.json");
        IOUtils.write(JSON.toJSONString(flowDetails, true), fileOutputStream);
    }

//    public static List simplifyFlow(List<MethodReference> methodReferences){
//        ArrayList<MethodReference> path = new ArrayList<>();
//        ArrayList<MethodReference> visited = new ArrayList<>();
//
//        for (MethodReference methodReference : methodReferences) {
//            if ((methodReference,path,visited)){
//                path.add(methodReference);
//            }
//        }
//        return path;
//    }
//    public static boolean s(MethodReference mrf,ArrayList path,ArrayList visited){
//        for (MethodReference methodReference : mapAllClass.get(mrf).methodList) {
//
//        }
//    }
}
