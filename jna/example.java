import org.radare2.rasm2;
import org.radare2.struct.RAsmOp;
public class example{
public static void main(String[] args){
try(rasm2 ras = new rasm2();){
ras.set_arch("x86",32);
String asm = "add eax ,1";
RAsmOp aop = ras.assemble(asm);
System.out.println("assemble : "+asm);
System.out.println("len : "+aop.get_size() + "\nhex : "+aop.get_hex());
String hex = "90";
RAsmOp aop2 = ras.disassemble(hex);
System.out.println("disassemble : "+hex);
System.out.println("len : "+aop2.get_size() + "\nasm : "+aop2.get_asm());
}
}
}