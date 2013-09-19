#include <iostream>
#include <Windows.h>
#include <sstream>

bool DumpPEFileInfo( const char* filename );
void ShowStructImageDosHeader( FILE* pFile , const _IMAGE_DOS_HEADER& header );
void ShowStructImageNTHeader( FILE* pFile , const IMAGE_NT_HEADERS32& header );
void ShowStructImageFileHeader( FILE* pFile ,  const IMAGE_FILE_HEADER& header );
void ShowStructImageOptionalHeader( FILE* pFile , const IMAGE_OPTIONAL_HEADER& header );
void ShowStructImageSectionHeader( FILE* pFile , const IMAGE_SECTION_HEADER& header) ;

int main( int argc,char *argv[] )
{
	if( 1 == argc )
	{
		std::cout<<"�޲���!"<<std::endl;
		return 0;
	}

	const char* fileName = argv[1];  
	DumpPEFileInfo( fileName );
	DumpPEFileInfo( "niparticle31vc90s.dll" );

	return 0;
}

bool DumpPEFileInfo( const char* filename )
{ 
	IMAGE_DOS_HEADER  imageDosHeader; //����ȡ��ImageDosͷ
	IMAGE_NT_HEADERS imageNTHeader;	   //����ȡ��ImageNTͷ

	memset( &imageDosHeader , 0 , sizeof(imageDosHeader) ); 
	memset( &imageNTHeader , 0 , sizeof(imageNTHeader) );


	//���Դ�PE�ļ�
	FILE* pPEFile = NULL;
	errno_t err = fopen_s( &pPEFile , filename , "rb" ); 
	if( 0 != err )
	{
		std::cout<<"�ļ�\""<<filename<<"\"������!"<<std::endl;
		return false;
	} 
	 
	size_t bytesRead = fread_s( &imageDosHeader , sizeof(imageDosHeader) , 1 , sizeof(imageDosHeader) , pPEFile );
	if( bytesRead != sizeof(imageDosHeader) )
	{
		std::cout<<"�ļ��е� IMAGE_DOS_HEADER �ṹ����!"<<std::endl;
		fclose( pPEFile );
		pPEFile = NULL;
		return 0;
	}

	//��λ��NTͷ����λ��
	int iRes = fseek( pPEFile , imageDosHeader.e_lfanew , SEEK_SET ); 
	if( 0 != iRes )
	{
		std::cout<<"�ļ�����!�޷���λ�� IMAGE_NT_HEADERS32 �ṹ��!"<<std::endl;
		fclose( pPEFile );
		pPEFile = NULL;
		return false;
	}  
	
	bytesRead = 
		fread_s( &imageNTHeader , sizeof(imageNTHeader) , 1 , sizeof(imageNTHeader) , pPEFile );


	bool bIsDebugVer = true; 
	if( imageNTHeader.FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED )
	{
		bIsDebugVer = false;
	}

	std::ostringstream strBumpFileName;  
	if( bIsDebugVer )
	{
		strBumpFileName<<filename<<"_"<<"Debug"<<"_"<<imageNTHeader.FileHeader.TimeDateStamp<<".txt";
	}else{
		strBumpFileName<<filename<<"_"<<"Release"<<"_"<<imageNTHeader.FileHeader.TimeDateStamp<<".txt";
	}

	FILE* pDumpFile = NULL;
	err = fopen_s( &pDumpFile , strBumpFileName.str().c_str() , "wt" );
	if( 0 != err )
	{
		std::cout<<"�ļ�\""<<strBumpFileName.str().c_str()<<"\"�޷���!"<<std::endl;
		fclose( pPEFile );
		pPEFile = NULL;
		return false;
	} 

	//չʾ_IMAGE_DOS_HEADER�ṹ��
	ShowStructImageDosHeader( pDumpFile ,  imageDosHeader );
	ShowStructImageNTHeader( pDumpFile , imageNTHeader );

	const int iSectionNum = imageNTHeader.FileHeader.NumberOfSections;

	for( int iSec = 0 ; iSec < iSectionNum ; iSec++ )
	{
		IMAGE_SECTION_HEADER imageSectionHeader;
		memset( &imageSectionHeader , 0 , sizeof(imageSectionHeader) );
		bytesRead = 
			fread_s( &imageSectionHeader , sizeof(imageSectionHeader) , 1 , sizeof(imageSectionHeader) , pPEFile );
		fprintf_s(  pDumpFile  , "\n\n[Section %d]\n" , iSec );
		ShowStructImageSectionHeader(  pDumpFile ,  imageSectionHeader );
	}

	//�ر�PE�ļ�
	fclose( pPEFile );
	pPEFile = NULL;

	fclose( pDumpFile );
	pDumpFile = NULL;
	return true;
}

void ShowStructImageDosHeader(  FILE* pFile , const _IMAGE_DOS_HEADER& header )
{ 
	 
	fprintf_s( pFile , "\n\n[Image_Dos_Header]\n");
	fprintf_s( pFile , "[ħ��] e_magic = 0x%.4x\n" , (unsigned int)header.e_magic  );
	fprintf_s( pFile , "[�ļ����ҳ���ֽ���] e_cblp = %d\n" ,  (unsigned int)header.e_cblp  );
	fprintf_s( pFile , "[�ļ�ҳ��] e_cp = %d\n" , (unsigned int)header.e_cp);
	fprintf_s( pFile , "[�ض���Ԫ�ظ���] e_crlc = %d\n" , (unsigned int)header.e_crlc  );
	fprintf_s( pFile , "[ͷ���ߴ磬�Զ���Ϊ��λ] e_cparhdr = %d\n" , (unsigned int)header.e_cparhdr  );
	fprintf_s( pFile , "[������С���Ӷ�] e_minalloc = %d\n" , (unsigned int)header.e_minalloc  );
	fprintf_s( pFile , "[������󸽼Ӷ�] e_maxalloc = %d\n" , (unsigned int)header.e_maxalloc  );
	fprintf_s( pFile , "[��ʼ��SSֵ(���ƫ����)] e_ss =  0x%.4x\n" , (unsigned int)header.e_ss  );
	fprintf_s( pFile , "[��ʼ��SPֵ] e_sp =  0x%.4x\n" , (unsigned int)header.e_sp  );
	fprintf_s( pFile , "[У���] e_csum =  0x%.4x\n" , (unsigned int)header.e_csum  );
	fprintf_s( pFile , "[��ʼ��IPֵ] e_ip = 0x%.4x\n" , (unsigned int)header.e_ip  );
	fprintf_s( pFile , "[��ʼ��CSֵ(���ƫ����)] e_cs = 0x%.4x\n" , (unsigned int)header.e_cs  );
	fprintf_s( pFile , "[�ط�����ļ���ַ] e_lfarlc = 0x%.4x\n" , (unsigned int)header.e_lfarlc  );
	fprintf_s( pFile , "[���Ǻ�] e_ovno = 0x%.4x\n" , (unsigned int)header.e_ovno  );
	fprintf_s( pFile , "[�ط�����ļ���ַ] e_lfarlc = %d\n" , (unsigned int)header.e_lfarlc  );
	fprintf_s( pFile , "[��exeͷ�����ļ���ַ] e_lfanew = %d\n" , (unsigned int)header.e_lfanew  );
};

void ShowStructImageNTHeader(  FILE* pFile , const IMAGE_NT_HEADERS& header  )
{
	fprintf_s( pFile , "\n\n[Image_NT_Header]\n");
	fprintf_s( pFile , "[PE�ļ�ͷ��־] Signature = 0x%.8x\n" , (unsigned int)header.Signature  );
	ShowStructImageFileHeader( pFile , header.FileHeader );
	ShowStructImageOptionalHeader( pFile , header.OptionalHeader );
}

void ShowStructImageFileHeader(  FILE* pFile , const IMAGE_FILE_HEADER& header )
{
	fprintf_s( pFile , "\n\n[Image_File_Header]\n");
	fprintf_s( pFile , "[ִ��ƽ̨] Machine = 0x%.4x\n" , (unsigned int)header.Machine  );
	fprintf_s( pFile , "[����Ŀ] NumberOfSections = %d\n" , (unsigned int)header.NumberOfSections  );
	fprintf_s( pFile , "[�ļ�����ʱ��] TimeDateStamp = %d\n" , (unsigned int)header.TimeDateStamp  );
	fprintf_s( pFile , "PointerToSymbolTable = %d\n" , (unsigned int)header.PointerToSymbolTable  );
	fprintf_s( pFile , "NumberOfSymbols = %d\n" , (unsigned int)header.NumberOfSymbols  );
	fprintf_s( pFile , "SizeOfOptionalHeader = %d\n" , (unsigned int)header.SizeOfOptionalHeader  );
	fprintf_s( pFile , "Characteristics =  0x%.4x\n" , (unsigned int)header.Characteristics  );
}

void ShowStructImageOptionalHeader(  FILE* pFile , const IMAGE_OPTIONAL_HEADER& header )
{
	fprintf_s( pFile , "\n\n[Image_Optional_Header]\n");
	fprintf_s( pFile , "Magic = 0x%.4x\n" ,  (unsigned int)header.Magic  );
	fprintf_s( pFile , "MajorLinkerVersion = %d\n" ,  (unsigned int)header.MajorLinkerVersion  );
	fprintf_s( pFile , "MinorLinkerVersion = %d\n" ,  (unsigned int)header.MinorLinkerVersion  );
	fprintf_s( pFile , "SizeOfCode = %d\n" ,  (unsigned int)header.SizeOfCode  );
	fprintf_s( pFile , "SizeOfInitializedData = %d\n" ,  (unsigned int)header.SizeOfInitializedData  );
	fprintf_s( pFile , "SizeOfUninitializedData = %d\n" ,  (unsigned int)header.SizeOfUninitializedData  );
	fprintf_s( pFile , "AddressOfEntryPoint = 0x%.8x\n" ,  (unsigned int)header.AddressOfEntryPoint  );
	fprintf_s( pFile , "BaseOfCode = 0x%.8x\n" ,  (unsigned int)header.BaseOfCode  );
	fprintf_s( pFile , "BaseOfData = 0x%.8x\n" ,  (unsigned int)header.BaseOfData  );
	fprintf_s( pFile , "ImageBase = 0x%.8x\n" ,  (unsigned int)header.ImageBase  );
	fprintf_s( pFile , "SectionAlignment = %d\n" ,  (unsigned int)header.SectionAlignment  );
	fprintf_s( pFile , "FileAlignment = %d\n" ,  (unsigned int)header.FileAlignment  );
	fprintf_s( pFile , "MajorOperatingSystemVersion = %d\n" ,  (unsigned int)header.MajorOperatingSystemVersion  );
	fprintf_s( pFile , "MinorOperatingSystemVersion = %d\n" ,  (unsigned int)header.MinorOperatingSystemVersion  );
	fprintf_s( pFile , "MajorImageVersion = %d\n" ,  (unsigned int)header.MajorImageVersion  );
	fprintf_s( pFile , "MinorImageVersion = %d\n" ,  (unsigned int)header.MinorImageVersion  );
	fprintf_s( pFile , "MajorSubsystemVersion = %d\n" ,  (unsigned int)header.MajorSubsystemVersion  );
	fprintf_s( pFile , "MinorSubsystemVersion = %d\n" ,  (unsigned int)header.MinorSubsystemVersion  );
	fprintf_s( pFile , "Win32VersionValue = %d\n" ,  (unsigned int)header.Win32VersionValue  );
	fprintf_s( pFile , "SizeOfImage = %d\n" ,  (unsigned int)header.SizeOfImage  );
	fprintf_s( pFile , "SizeOfHeaders = %d\n" ,  (unsigned int)header.SizeOfHeaders  );
	fprintf_s( pFile , "CheckSum = %d\n" ,  (unsigned int)header.CheckSum  );
	fprintf_s( pFile , "Subsystem = %d\n" ,  (unsigned int)header.Subsystem  );
	fprintf_s( pFile , "DllCharacteristics = %d\n" ,  (unsigned int)header.DllCharacteristics  );
	fprintf_s( pFile , "SizeOfStackReserve = %d\n" ,  (unsigned int)header.SizeOfStackReserve  );
	fprintf_s( pFile , "SizeOfStackCommit = %d\n" ,  (unsigned int)header.SizeOfStackCommit  );
	fprintf_s( pFile , "SizeOfHeapReserve = %d\n" ,  (unsigned int)header.SizeOfHeapReserve  );
	fprintf_s( pFile , "SizeOfHeapCommit = %d\n" ,  (unsigned int)header.SizeOfHeapCommit  );
	fprintf_s( pFile , "LoaderFlags = %d\n" ,  (unsigned int)header.LoaderFlags  );
	fprintf_s( pFile , "NumberOfRvaAndSizes = %d\n" ,  (unsigned int)header.NumberOfRvaAndSizes  );

	for( int i = 0 ; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ; i++ )
	{
		fprintf_s( pFile , "\t\t [Directory %d]:\n" , i );
		fprintf_s( pFile , "\t\t\t VirtualAddress = 0x%.8x\n" , header.DataDirectory[i].VirtualAddress );
		fprintf_s( pFile , "\t\t\t Size = %d\n" , header.DataDirectory[i].Size );
	}
}

void ShowStructImageSectionHeader(  FILE* pFile , const IMAGE_SECTION_HEADER& header )
{
	fprintf_s( pFile , "Name = \"%s\"\n" , header.Name );
	fprintf_s( pFile , "Misc.VirtualSize = %d\n" , header.Misc.VirtualSize );
	fprintf_s( pFile , "VirtualAddress = 0x%.8x\n" , header.VirtualAddress );
	fprintf_s( pFile , "SizeOfRawData = %d\n" , header.SizeOfRawData  );
	fprintf_s( pFile , "PointerToRawData = %d\n" , header.PointerToRawData   );
	fprintf_s( pFile , "PointerToRelocations = %d\n" , header.PointerToRelocations    );
	fprintf_s( pFile , "NumberOfRelocations = %d\n" , header.NumberOfRelocations  );
	fprintf_s( pFile , "NumberOfLinenumbers = %d\n" , header.NumberOfLinenumbers );
	fprintf_s( pFile , "Characteristics = 0x%.8x\n" , header.Characteristics  );
}



