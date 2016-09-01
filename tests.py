import unittest
from challenge import check4xss

#Test unit for check4xss 
#using the Rnake xss cheat sheet

#config for white-list HTML tags and Attributes
tags = {'a' : ['href'] , 'b': ['font-weight'] , 
'br': ['class','id', 'style', 'hidden'], 
'em': ['class','id', 'style', 'hidden'], 
'i': ['class','id', 'style', 'hidden'], 
'mark': ['class','id', 'style', 'hidden'], 
'p': ['class','id', 'style', 'hidden'], 
'span': ['class','id', 'style', 'hidden'], 
'strong': ['class','id', 'style', 'hidden'] }



class TestXss(unittest.TestCase):
	#tests for the Rnake xss cheat sheet
	def test_xss_Rsnake1(self):

		parameter = "';!--<XSS>=&{()}"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake2(self):

		parameter = "<IMG SRC=""javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags ))
	def test_xss_Rsnake3(self):

		parameter ="<IMG SRC=javascript:alert('XSS')>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake4(self):

		parameter ="<IMG SRC=JaVaScRiPt:alert('XSS')>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake5(self):

		parameter ="<IMG SRC=JaVaScRiPt:alert(&quot;XSS&quot;)>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake6(self):

		parameter ="<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41>"
		self.assertTrue(check4xss(parameter, tags))
		
	def test_xss_Rsnake7(self):

		parameter ="<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"
		self.assertTrue(check4xss(parameter, tags))
		
	def test_xss_Rsnake8(self):

		parameter ="<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"
		self.assertTrue(check4xss(parameter, tags))

	def test_xss_Rsnake9(self):

		parameter ="<IMG SRC=""jav&#x09;ascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake10(self):

		parameter ="<IMG SRC=""jav&#x0A;ascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake11(self):

		parameter ="<IMG SRC=""jav&#x0D;ascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake12(self):

		parameter ="<IMG SRC=""   javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake13(self):

		parameter ="<SCRIPT>a=/XSS/""alert(a.source)</SCRIPT>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake14(self):

		parameter ="<BODY BACKGROUND=""javascript:alert('XSS')"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake15(self):

		parameter ="<BODY ONLOAD=alert('XSS')>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake16(self):

		parameter ="<IMG DYNSRC=""javascript:alert('XSS')"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake17(self):

		parameter ="<INPUT TYPE=""image"" DYNSRC=""javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake18(self):

		parameter ="<br size=""&{alert('XSS')}"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake19(self):

		parameter ="<LAYER SRC=""http://xss.ha.ckers.org/a.js""></layer>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake20(self):

		parameter ="<LINK REL=""stylesheet"" HREF=""javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake21(self):
		parameter ='<IMG SRC=''vbscript:msgbox("XSS")''>'
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake22(self):

		parameter ="<META HTTP-EQUIV=""refresh"" CONTENT=""0;url=javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake23(self):

		parameter ="<IFRAME SRC=javascript:alert('XSS')></IFRAME>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake24(self):

		parameter ="<FRAMESET><FRAME SRC=javascript:alert('XSS')></FRAME></FRAMESET>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake25(self):

		parameter ="<TABLE BACKGROUND=""javascript:alert('XSS')"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake26(self):

		parameter ="<DIV STYLE=""background-image: url(javascript:alert('XSS'))"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake27(self):

		parameter ="<DIV STYLE=""behaviour: url('http://xss.ha.ckers.org/exploit.htc');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake28(self):

		parameter ="<DIV STYLE=""width: expression(alert('XSS'));"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake29(self):

		parameter ='<IMG STYLE=''xss:expre\ssion(alert(""XSS""))''>'
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake30(self):

		parameter ='<STYLE TYPE="text/javascript">alert(''XSS'');</STYLE>'
		#print(parameter)
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake31(self):

		parameter ="<STYLE TYPE=""text/css"">.XSS{background-image:url(""javascript:alert('XSS')"");}</STYLE><A CLASS=XSS></A>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake32(self):

		parameter ="<BASE HREF=""javascript:alert('XSS');//"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake33(self):

		parameter ="<OBJECT data=http://xss.ha.ckers.org width=400 height=400 type=text/x-scriptlet"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake34(self):

		parameter ='getURL("javascript:alert(''XSS'')")'
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake35(self):

		parameter ="<XML SRC=""javascript:alert('XSS');"">"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake36(self):

		parameter ="> <BODY ONLOAD=""a();""><SCRIPT>function a(){alert('XSS');}</SCRIPT><"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake37(self):

		parameter ="<SCRIPT SRC=""http://xss.ha.ckers.org/xss.jpg""></SCRIPT>"
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake38(self):

		parameter ='<IMG SRC=""javascript:alert(''XSS'')""'
		self.assertTrue(check4xss(parameter, tags))
	def test_xss_Rsnake39(self):

		parameter ="<IMG SRC=""http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode"">"
		self.assertTrue(check4xss(parameter, tags))
if __name__ == '__main__':
    unittest.main()