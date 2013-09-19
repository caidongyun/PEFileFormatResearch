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
		std::cout<<"无参数!"<<std::endl;
		return 0;
	}

	const char* fileName = argv[1];  
	DumpPEFileInfo( fileName );
	DumpPEFileInfo( "niparticle31vc90s.dll" );

	return 0;
}

bool DumpPEFileInfo( const char* filename )
{ 
	IMAGE_DOS_HEADER  imageDosHeader; //待读取的ImageDos头
	IMAGE_NT_HEADERS imageNTHeader;	   //待读取的ImageNT头

	memset( &imageDosHeader , 0 , sizeof(imageDosHeader) ); 
	memset( &imageNTHeader , 0 , sizeof(imageNTHeader) );


	//尝试打开PE文件
	FILE* pPEFile = NULL;
	errno_t err = fopen_s( &pPEFile , filename , "rb" ); 
	if( 0 != err )
	{
		std::cout<<"文件\""<<filename<<"\"不存在!"<<std::endl;
		return false;
	} 
	 
	size_t bytesRead = fread_s( &imageDosHeader , sizeof(imageDosHeader) , 1 , sizeof(imageDosHeader) , pPEFile );
	if( bytesRead != sizeof(imageDosHeader) )
	{
		std::cout<<"文件中的 IMAGE_DOS_HEADER 结构破损!"<<std::endl;
		fclose( pPEFile );
		pPEFile = NULL;
		return 0;
	}

	//定位到NT头所在位置
	int iRes = fseek( pPEFile , imageDosHeader.e_lfanew , SEEK_SET ); 
	if( 0 != iRes )
	{
		std::cout<<"文件破损!无法定位到 IMAGE_NT_HEADERS32 结构体!"<<std::endl;
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
		std::cout<<"文件\""<<strBumpFileName.str().c_str()<<"\"无法打开!"<<std::endl;
		fclose( pPEFile );
		pPEFile = NULL;
		return false;
	} 

	//展示_IMAGE_DOS_HEADER结构体
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

	//关闭PE文件
	fclose( pPEFile );
	pPEFile = NULL;

	fclose( pDumpFile );
	pDumpFile = NULL;
	return true;
}

void ShowStructImageDosHeader(  FILE* pFile , const _IMAGE_DOS_HEADER& header )
{ 
	 
	fprintf_s( pFile , "\n\n[Image_Dos_Header]\n");
	fprintf_s( pFile , "[魔数] e_magic = 0x%.4x\n" , (unsigned int)header.e_magic  );
	fprintf_s( pFile , "[文件最后页的字节数] e_cblp = %d\n" ,  (unsigned int)header.e_cblp  );
	fprintf_s( pFile , "[文件页数] e_cp = %d\n" , (unsigned int)header.e_cp);
	fprintf_s( pFile , "[重定义元素个数] e_crlc = %d\n" , (unsigned int)header.e_crlc  );
	fprintf_s( pFile , "[头部尺寸，以段落为单位] e_cparhdr = %d\n" , (unsigned int)header.e_cparhdr  );
	fprintf_s( pFile , "[所需最小附加段] e_minalloc = %d\n" , (unsigned int)header.e_minalloc  );
	fprintf_s( pFile , "[所需最大附加段] e_maxalloc = %d\n" , (unsigned int)header.e_maxalloc  );
	fprintf_s( pFile , "[初始的SS值(相对偏移量)] e_ss =  0x%.4x\n" , (unsigned int)header.e_ss  );
	fprintf_s( pFile , "[初始的SP值] e_sp =  0x%.4x\n" , (unsigned int)header.e_sp  );
	fprintf_s( pFile , "[校验和] e_csum =  0x%.4x\n" , (unsigned int)header.e_csum  );
	fprintf_s( pFile , "[初始的IP值] e_ip = 0x%.4x\n" , (unsigned int)header.e_ip  );
	fprintf_s( pFile , "[初始的CS值(相对偏移量)] e_cs = 0x%.4x\n" , (unsigned int)header.e_cs  );
	fprintf_s( pFile , "[重分配表文件地址] e_lfarlc = 0x%.4x\n" , (unsigned int)header.e_lfarlc  );
	fprintf_s( pFile , "[覆盖号] e_ovno = 0x%.4x\n" , (unsigned int)header.e_ovno  );
	fprintf_s( pFile , "[重分配表文件地址] e_lfarlc = %d\n" , (unsigned int)header.e_lfarlc  );
	fprintf_s( pFile , "[新exe头部的文件地址] e_lfanew = %d\n" , (unsigned int)header.e_lfanew  );
};

void ShowStructImageNTHeader(  FILE* pFile , const IMAGE_NT_HEADERS& header  )
{
	fprintf_s( pFile , "\n\n[Image_NT_Header]\n");
	fprintf_s( pFile , "[PE文件头标志] Signature = 0x%.8x\n" , (unsigned int)header.Signature  );
	ShowStructImageFileHeader( pFile , header.FileHeader );
	ShowStructImageOptionalHeader( pFile , header.OptionalHeader );
}

void ShowStructImageFileHeader(  FILE* pFile , const IMAGE_FILE_HEADER& header )
{
	fprintf_s( pFile , "\n\n[Image_File_Header]\n");
	fprintf_s( pFile , "[执行平台] Machine = 0x%.4x\n" , (unsigned int)header.Machine  );
	fprintf_s( pFile , "[段数目] NumberOfSections = %d\n" , (unsigned int)header.NumberOfSections  );
	fprintf_s( pFile , "[文件建立时间] TimeDateStamp = %d\n" , (unsigned int)header.TimeDateStamp  );
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



