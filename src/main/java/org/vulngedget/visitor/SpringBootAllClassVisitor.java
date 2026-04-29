package org.vulngedget.visitor;

import org.objectweb.asm.*;

import org.vulngedget.reference.*;
import org.vulngedget.util.AnnotationUtil;
import org.vulngedget.util.Opcode;

import java.util.*;
import static org.vulngedget.cache.DataCache.*;

/**
 * A controller class needs to satisfy
 * in class: @controller @RestController [@RequestMapping]
 * in method @*Mapping [@RequestMapping, @GetMapping, @PostMapping, @PutMapping...]
 */
public class SpringBootAllClassVisitor extends ClassVisitor {

    //鎵弿.class鏂囦欢鐨勭被鍚?
    private String className;
    //classReference鏄敤鏉ヤ繚鐣欑被淇℃伅鐨勭被, 鍚庣画闇€瑕佷娇鐢ㄧ殑
    private ClassReference classReference;
    //obj -> [path]

    //.class鐨勪簩杩涘埗鏁版嵁, 鍚庣画鍙互鏍规嵁绫诲悕鎵惧埌瀵瑰簲鐨?class绫?
    private byte[] data;


    //鏋勯€犳柟娉? 灏嗕簩杩涘埗鏁版嵁璧嬪€?
    public SpringBootAllClassVisitor(byte[] d) {
        super(Opcode.ASM_V);
        data = d;
    }

    @Override
    //visit鏂规硶鏄痑sm鍒嗘瀽.class鏈€鍒濊皟鐢ㄧ殑涓€涓柟娉? 閲岄潰鏈夊悇绉嶅熀鏈俊鎭?
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {

        this.className = name;
        //鍒涘缓classReference鐨勫璞?
        this.classReference = new ClassReference();
        //淇濆瓨鎺ュ彛淇℃伅
        classReference.interfacesList = Arrays.asList(interfaces);
        //淇濆瓨绫诲悕淇℃伅
        classReference.className = name;
        //淇濆瓨鐖剁被淇℃伅, 鍚庣画鍦ㄥ鎵剧埗瀛愮被鏂规硶鐨勮皟鐢ㄧ殑鏃跺€欐湁鐢?
        classReference.superClassName = superName;
        //纭畾璇ョ被鏄惁涓篿nterface, 鍚庣画涔熸槸闇€瑕佹牴鎹帴鍙ｇ被鏉ユ壘瀹炵幇绫?
        if ((access & Opcodes.ACC_INTERFACE) !=0){
            classReference.isInterface = true;
        }
        //杩欓噷淇濆瓨姣忎釜绫诲拰绫讳俊鎭殑瀵瑰簲鍏崇郴
        mapAllClass.put(className,classReference);
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        List<String> annontaionDescList = AnnotationUtil.controllerClassAnnotaionDescList;
        for (String annotationDesc : annontaionDescList) {
            if (annotationDesc.equals(descriptor)) {
                if (!allControllerClass.contains(classReference)){
                 allControllerClass.add(classReference);
                }
                break;
            }
        }
        return super.visitAnnotation(descriptor, visible);
    }


    @Override
    //杩欎釜鏂规硶鏄痑sm鐢ㄦ潵鍒嗘瀽绫讳腑鏂规硶鐨?
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        /**
         * add method
         */
        //鍒涘缓濂組ethodReference, 鐢ㄦ潵淇濆瓨鏂规硶涓殑淇℃伅, 姣斿鏂规硶涓殑鏂规硶璋冪敤
        MethodReference methodReference = new MethodReference();
        //杩欓噷闇€瑕佷繚瀛樻柟娉曞拰绫荤殑瀵瑰簲淇℃伅
        methodReference.className = className;
        //淇濆瓨鏂规硶鍚?
        methodReference.methodName = name;
        //desc琛ㄧず鐨勫氨鏄柟娉曟帴鍙椾粈涔堝弬鏁? 杩斿洖浠€涔堟暟鎹? 姣斿浠€涔堟柟娉曢兘涓嶆帴鍙椾粈涔堥兘涓嶈繑鍥炲氨鏄?)V
        methodReference.desc = descriptor;
        //allMethodReferenceList闈炲父閲嶈, 淇濆瓨浜嗘墍鏈夋柟娉曠殑淇℃伅
        allMethodReferenceList.add(methodReference);
        //杩欓噷鍦╟lassReference涓繚瀛樻湁鍝簺鏂规硶
        classReference.methodList.add(methodReference);
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
        //璺宠繃闈欐€佷唬鐮佸潡, 涓嶈€冭檻浜?
        if (!name.equals("<clinit>")) {
            //todo

            //涓嶄负闈欐€佷唬鐮佸潡鐨勮瘽灏辩敤AllClassMethodVisitor杩欎釜绫绘潵瑙ｆ瀽鏂规硶涓殑淇℃伅
            return new AllClassMethodVisitor(api, methodVisitor, methodReference);
        }
        return methodVisitor;
    }

    @Override
    //visitEnd鏄痑sm鍦ㄥ垎鏋愬畬鎴愬悗浼氳皟鐢ㄧ殑涓€涓柟娉? 杩欓噷淇濆瓨浜嗙被鍜屼簩杩涘埗.class淇℃伅鐨勫搴斿叧绯?
    public void visitEnd() {
        classResources.put(className,data);
        super.visitEnd();
    }

    private class AllClassMethodVisitor extends MethodVisitor {

        private MethodReference methodReference;
        private String method;

        public AllClassMethodVisitor(int api, MethodVisitor methodVisitor, MethodReference methodReference) {
            super(api, methodVisitor);
            this.methodReference = methodReference;
        }



        @Override
        //杩欎釜鏂规硶鐢ㄦ潵瑙ｆ瀽鏂规硶涓殑娉ㄨВ
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            //杩欓噷鍙鏄互mapping缁撳熬鐨?閮藉彲浠ュ仛涓簊ource, 姣斿GetMapping, PostMapping杩欎簺,閮芥槸mapping缁撳熬鐨?
            if (AnnotationUtil.controllerMathodAnnotaionDescList.contains(descriptor) || descriptor.endsWith("Mapping;")) {
                methodReference.isControllerMethod = true;
            }
            return super.visitAnnotation(descriptor, visible);
        }

        @Override
        //visitMethodInsn琛ㄧず: 鏂规硶涓彧瑕佸瓨鍦ㄦ柟娉曡皟鐢ㄥ氨浼氭墽琛屽埌杩欓噷
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            //鍦ㄨ繖閲屽垱寤轰竴涓狹ethodReference, owner琛ㄧず鎵€灞炵被, 姣斿a鏂规硶涓皟鐢ㄤ簡b绫讳腑鐨刢鏂规硶, 閭wner灏辨槸c
            MethodReference m = new MethodReference();
            m.className = owner;
            m.methodName = name;
            m.desc = descriptor;
            //杩欓噷娣诲姞鍒癱alledMethodList閲岄潰, 鍚庣画灏卞彲浠ユ牴鎹瘡涓狹ethodReference鏉ユ瀯寤哄畬鏁寸殑璋冪敤娴佷簡
            methodReference.calledMethodList.add(m);
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}


