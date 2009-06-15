
#include "bignumber.h"
#include <iostream>

bool isZero( const DIGIT bn[], const unsigned num ){
	unsigned i=0;
	while (i<num && bn[i] == 0)
		i++;
	return i==num;
}

int bncmp( const DIGIT bn1[], const DIGIT bn2[], const unsigned num ){
	unsigned i=num-1;
	while (i+1>0 && bn1[i] == bn2[i])
		i--;
	if ( i+1 == 0)
		return 0;
	else if (bn1[i]>bn2[i])
		return 1;
	else
		return -1;
}

// сложение двух длинных чисел: 
//		res = bn1 + bn2
// возвращает:
//		бит переноса
DIGIT add( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num ){
	DIGIT d=0;
	for (unsigned i=0; i<num; i++){
		TWODIGIT T = TWODIGIT(bn1[i]) + bn2[i] + d;
		res[i] = lodigit( T );
		d = hidigit( T );
	}
	return d;
}

// сложение двух длинных чисел: 
//		res = bn1 + bn2
// возвращает:
//		бит переноса
DIGIT addDigit( DIGIT res[], const DIGIT bn1[], const DIGIT x, const unsigned num ){
	DIGIT d=x;
	unsigned i=0;
	while (d>0 && i<num){
		TWODIGIT T = TWODIGIT(bn1[i]) + d;
		res[i] = lodigit( T );
		d = hidigit( T );
		i++;
	}
	return d;
}

// вычитание двух длинных чисел:
//		res = bn1 - bn2
// возвращает:
//		бит заема
DIGIT sub( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num ){
	DIGIT d=0;
	for (unsigned i=0; i<num; i++){
		TWODIGIT T = TWODIGIT(bn1[i]) - bn2[i] - d;
		res[i] = lodigit( T );
		d = hidigit( T );
		d = 0-d;
	}
	return d;	
}

// вычитание цифры из длинного числа:
//		res = bn1 - bn2
// возвращает:
//		бит заема
DIGIT subDigit( DIGIT res[], const DIGIT bn1[], const DIGIT x, const unsigned num ){
	DIGIT d=x;
	for (unsigned i=0; i<num; i++){
		TWODIGIT T = TWODIGIT(bn1[i]) - d;
		res[i] = lodigit( T );
		d = hidigit( T );
		d = 0-d;
	}
	return d;	
}

// умножение двух длинных чисел:
//		res = bn1*bn2;
// реализован алгоритм умножения столбиком
// возвращает:
//		<ничего>
void mul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num ){
	zero(res, num);
	for(unsigned i=0; i<num; i++){
		DIGIT d = 0;
		for ( unsigned j=0; j<num; j++){
			TWODIGIT T = TWODIGIT( bn1[i] ) * bn2[j] + TWODIGIT(res[i+j]) + d;
			res[i+j] = lodigit( T );
			d = hidigit( T );
		}
		res[i+num] = d;
	}
}

// умножение цифры на длинное число:
//		res = bn1*bn2;
// возвращает:
//		<ничего>
void shortMul( DIGIT res[], const DIGIT bn[], const DIGIT x, const unsigned num ){
	DIGIT d=0;
	for (unsigned i=0; i<num; i++){
		TWODIGIT T = TWODIGIT(bn[i])*x + TWODIGIT(d);
		res[i] = lodigit( T );
		d = hidigit( T );
	}
	res[num] = d;		
}

// деление длинного числа на цифру с вычислением остатка от деления:
//      bnQuo = [bn1/bn2]
//		bnRem = bn1 mod bn2;
// возвращает:
//		<ничего>
void shortDiv( DIGIT *res, const DIGIT bn[], DIGIT x, DIGIT *rem, unsigned num ){
	if ( x==0 ) 
		return;
	TWODIGIT T = 0;
	for (unsigned i = num-1; i+1>0; i--){
		T = makelong( bn[i], lodigit(T));
		if ( res != NULL )
			res[i] = lodigit( T/x);
		T %= x;
	}
	if ( rem != NULL ) {
		zero( rem, num );
		*rem = lodigit( T );
	}
}

// деление длинного числа на длинное число с вычислением остатка от деления:
//      bnQuo = [bn1/bn2]
//		bnRem = bn1 mod bn2;
// возвращает:
//		<ничего>
void div( const DIGIT bn1[], const DIGIT bn2[], DIGIT *bnQuo, DIGIT *bnRem, const unsigned num1, const unsigned num2 ){
	unsigned i,k, n1 = num1, n2=num2;
	for (i=n2-1; i+1>0 && bn2[i]==0; i--)
		;
	n2 = i+1;
	if ( n2 == 0 )
		return;
	for (k=n1-1; k+1>0 && bn1[k]==0; k--)
		;
	n1 = k+1;
	if (n2 > n1 ){
		if ( bnRem != NULL )
			assign( bnRem, bn1, num2);
		if ( bnQuo != NULL )
			zero( bnQuo, num1 );
		return;
	}
	else if (n2 == 1 ) {
		shortDiv( bnQuo, bn1, bn2[0], bnRem, num1 );
		return;
	}
	// нормализация
	DIGIT d = DIGIT( (TWODIGIT( MAX_DIGIT ) + 1) /(TWODIGIT(bn2[n2-1]) + 1));
	DIGIT u[MAX_SIZE*2+2];	// нормализованное делимое
	DIGIT v[MAX_SIZE+1];	// нормализованный делитель
	DIGIT w[MAX_SIZE+1];	// промежуточные результаты
	shortMul( v, bn2, d, n2 );
	shortMul( u, bn1, d, n1 );
	u[n1+1] = 0;
	// очищаем именно здесь для того, чтобы можно было 
	// подставлять одни аргументы сразу и в качестве делимого и частного/остатка, например
	if ( bnRem != NULL )
		zero( bnRem, num2);
	if ( bnQuo != NULL )
		zero( bnQuo, num1);

	for (unsigned j=n1; j>=n2; j--){
		TWODIGIT T = makelong ( u[j-1], u[j] );
		DIGIT q;
		if (u[j]==v[n2-1])
			q = MAX_DIGIT;
		else
			q = DIGIT( T/v[n2-1]);
		T %= v[n2-1];

		if ( TWODIGIT(v[n2-2])*q > makelong( u[j-2], DIGIT(T))){
			q--;
			//std::cout << "-";
		}
		T += v[n2-1];
		if ( T < TWODIGIT(MAX_DIGIT)+1 && TWODIGIT(v[n2-2])*q > makelong( u[j-2], DIGIT(T)) ){
			q--;
			//std::cout << "+";
		}

		shortMul( w,v,q,n2);
		u[j+1] = sub( u + j - n2, u+j-n2, w, n2+1);
		if ( u[j+1] ){
			u[j+1] = add( u+j-n2, u+j-n2, v, n2);
			q--;
			
		}
		if ( bnQuo != NULL ) 
			bnQuo[j-n2] = q;
	}
	if ( bnRem != NULL )
		shortDiv( bnRem, u, d, NULL, n2);
}

// умножение двух длинных чисел по модулю:
//		res = bn1*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modmul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num ){
	DIGIT temp[2*MAX_SIZE];
	mul( temp, bn1, bn2, num);
	div( temp, bnMod, NULL, res, 2*num, num);
}

// умножение двух длинных чисел по Монтгомери:
//		res = bn1*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void montMul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], DIGIT z, const unsigned num ){
	
	DIGIT T[MAX_SIZE+1];
	TWODIGIT ulTmp;
	DIGIT uiTmp, e;
	zero( T, num+1);
	for (unsigned i=0; i< num; i++){
		// T += bn1 * bn2[i]
		ulTmp = 0;
		uiTmp = bn2[i];
		for (unsigned j=0; j<num; j++){
			ulTmp = (TWODIGIT) bn1[j] * uiTmp + (TWODIGIT) hidigit( ulTmp ) + TWODIGIT( T[j] );
			T[j] = lodigit( ulTmp );
		}
		T[num] += hidigit(ulTmp);
		e = T[0]*z;
		// T += e*bnMod и сдвиг влево
		ulTmp = TWODIGIT(e)*bnMod[0] + TWODIGIT( T[0]);
		for (unsigned j=1; j<num; j++){
			ulTmp = TWODIGIT( e ) * bnMod[j] + TWODIGIT(hidigit( ulTmp ) ) + TWODIGIT( T[j] );
			T[j-1] = lodigit( ulTmp );
		}
		ulTmp = TWODIGIT( hidigit(ulTmp) ) + TWODIGIT( T[num] );
		T[num-1] = lodigit( ulTmp );
		T[num] = hidigit( ulTmp );
	}
	if ( T[num] )
		sub( T, T, bnMod, num);
	while( bncmp( T, bnMod, num) >=0 )
		sub( T, T, bnMod, num );
	assign( res, T, num );
}

void gf2mf( DIGIT res[], const DIGIT bn[], const DIGIT bnMod[], unsigned num ){
	DIGIT bnTemp[MAX_SIZE*2];
	zero( bnTemp, num );
	assign( &bnTemp[num], bn, num );
	div( bnTemp, bnMod, NULL, res, 2*num, num );
}

void mf2gf( DIGIT res[], const DIGIT bn[], const DIGIT bnMod[], DIGIT z, unsigned num ){
	DIGIT bnTemp[MAX_SIZE];
	assignDigit( bnTemp, 1, num );
	montMul( res, bn, bnTemp, bnMod, z, num);
}

DIGIT findz( const DIGIT x ){
	if ( (x&1 ) == 0 )
		return 0;
	DIGIT d = x;
	for (unsigned i=0; i<baseDigits-2; i++){
		d *= d;
		d *= x;
	}
	return (0-d);
}

// умножение цифры на длинное число по модулю:
//		res = x*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modmulShort( DIGIT res[], const DIGIT bn1[], const DIGIT x, const DIGIT bnMod[], const unsigned num ){
	DIGIT temp[MAX_SIZE+1];
	shortMul( temp, bn1, x, num);
	div( temp, bnMod, NULL, res, num+1, num);
}

void print( const DIGIT bn[], const unsigned num ){
	static const char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	for ( unsigned i=num-1; i+1>0; i--){
		DIGIT temp = bn[i];
		char representation[baseDigits / 4];
		for (unsigned j = 0; j<baseDigits / 4; j++){
			representation[j] = table[temp % 16];
			temp = temp/16;
		}
		for (unsigned j = baseDigits / 4 -1; j+1>0; j--)
			std::cout << representation[j];
	}
}

inline std::ostream& operator<<( std::ostream &os, const DIGIT* bn){
	static const char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	for ( unsigned i=MAX_SIZE-1; i+1>0; i--){
		DIGIT temp = bn[i];
		char representation[baseDigits / 4];
		for (unsigned j = 0; j<baseDigits / 4; j++){
			representation[j] = table[temp % 16];
			temp = temp/16;
		}
		for (unsigned j = baseDigits / 4 -1; j+1>0; j--)
			os << representation[j];
	}
	return os;
}


std::ostream& operator<<( std::ostream &os, const BigNum &bn){
	static const char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	for ( unsigned i=MAX_SIZE-1; i+1>0; i--){
		DIGIT temp = bn[i];
		char representation[baseDigits / 4];
		for (unsigned j = 0; j<baseDigits / 4; j++){
			representation[j] = table[temp % 16];
			temp = temp/16;
		}
		for (unsigned j = baseDigits / 4 -1; j+1>0; j--)
			os << representation[j];
	}
	return os;
}

/*
void square( DIGIT res[], const DIGIT bn[], const unsigned num ){
	mul( res, bn, bn, num );
	
	zero( res, 2*num );
	for( unsigned i=0; i<num; i++){
		TWODIGIT f = 0;
		TWODIGIT t;
		for (unsigned j=0; j<i; j++){
			t = TWODIGIT(bn[i])*TWODIGIT(bn[j]);
			f += ( TWODIGIT(lodigit(t)) << 1 ) + res[i+j];
			res[i+j] = lodigit(f);
			f = hidigit(f);
			f += (TWODIGIT( hidigit(t)) << 1 );
		}
		t = TWODIGIT( bn[i] ) * TWODIGIT( bn[i] );
		f += lodigit(t) + res[i+i];
		res[i+i] = lodigit(f);
		f = hidigit(f) + res[i+i+1] + hidigit(t);
		res[i+i+1] = lodigit(f);
		res[i+i+2] = hidigit(f);
	}
	
}
*/

/*
// возведение в степень длинного числа по модулю:
//		res = bnBase^bnDegree (mod bnMod);
// возвращает:
//		<ничего>
void modPower( DIGIT res[], const DIGIT bnBase[], const DIGIT bnDegree[], const DIGIT bnMod[], const unsigned numDegree, const unsigned numMod ){
	assignDigit( res, 1, numMod );
	for ( unsigned i = numDegree - 1; i+1>0; i--)
		for (unsigned j=baseDigits-1; j+1>0; j--){
			modSquare( res,res, bnMod, numMod );
			if ( ( bnDegree[i] >> j) &1)
				modmul( res, res, bnBase, bnMod, numMod);
		}
}
*/

inline void montSquare( DIGIT res[], const DIGIT bn[], const DIGIT bnMod[], const DIGIT z, const unsigned num ){
	montMul( res, bn, bn, bnMod, z, num );
}

// возведение в степень длинного числа по модулю с использованием операции Монтгомери:
//		res = bnBase^bnDegree (mod bnMod);
// возвращает:
//		<ничего>
void modPowerMont( DIGIT res[], const DIGIT bnBase[], const DIGIT bnDegree[], const DIGIT bnMod[], const unsigned numDegree, const unsigned numMod ){
	DIGIT z = findz( bnMod[0] );
	DIGIT bnTemp[MAX_SIZE];
	assignDigit( res, 1 , numMod);
	gf2mf( res, res, bnMod, numMod);
	gf2mf( bnTemp, bnBase, bnMod, numMod );
	for ( unsigned i = numDegree - 1; i+1>0; i--)
		for (unsigned j=baseDigits-1; j+1>0; j--){
			montSquare( res,res, bnMod, z, numMod );
			if ( ( bnDegree[i] >> j) &1)
				montMul( res, res, bnTemp, bnMod, z, numMod);
		}
	mf2gf( res, res, bnMod, z, numMod );
}

/*
void gcd(DIGIT bnGCD[], const DIGIT bnA[], const DIGIT bnB[], DIGIT bnX[], DIGIT bnY[], bool &bXNegative, bool &bYNegative, const unsigned num ){
	bXNegative = false;
	bYNegative = true;
	//bool bOverfull = false;
	if ( isZero( bnB, num ) ){
		if ( bnGCD != NULL )
			assign( bnGCD, bnA, num );
		if (bnX !=NULL)
			assignDigit( bnX, 1, num );
		if (bnY != NULL )
			zero( bnY, num );
		bYNegative = false;
		return;
	}
	DIGIT bnX1[MAX_SIZE], bnX2[MAX_SIZE], bnY1[MAX_SIZE], bnY2[MAX_SIZE], bnA1[MAX_SIZE], bnB1[MAX_SIZE];
	assign( bnA1, bnA, num );
	assign( bnB1, bnB, num );
	if (bnX != NULL ){
		assignDigit( bnX2, 1, num );
		zero( bnX1, num );	
	}
	if ( bnY != NULL ){
		assignDigit( bnY1, 1, num );
		zero( bnY2, num );
	}
	while ( !isZero( bnB1, num )) {
		bXNegative = !bXNegative;
		bYNegative = !bYNegative;
		DIGIT bnQ[MAX_SIZE];
		DIGIT bnR[MAX_SIZE];
		div( bnA1, bnB1, bnQ, bnR, num, num );
		assign( bnA1, bnB1, num );
		assign( bnB1, bnR, num );
		if ( bnX != NULL ){
			DIGIT bnTemp[2*MAX_SIZE];
			mul( bnTemp, bnX1, bnQ, num );
#ifdef _VERBOSE_CHECKING
			bool bOverfull = false;
			for (unsigned i=num; i< 2*num; i++)
				bOverfull = bOverfull || (bnTemp[i] != 0 );
			if ( bOverfull ){
				std::cout << "Overfull in extended eucklid algorithm in bnTemp calculation (X branch)\n";
				print(bnTemp, 2*num); std::cout<< std::endl;
				print(bnX1, num); std::cout<< std::endl;
				print(bnQ, num); std::cout<< std::endl;
			}
#endif
			add( bnTemp, bnX2, bnTemp, num);
			assign( bnX2, bnX1, num );
			assign( bnX1, bnTemp, num );
		}
		
		if ( bnY != NULL ){
			DIGIT bnTemp[2*MAX_SIZE];
			mul( bnTemp, bnY1, bnQ, num );
#ifdef _VERBOSE_CHECKING
			bool bOverfull = false;
			for (unsigned i=num; i< 2*num; i++)
				bOverfull = bOverfull || (bnTemp[i] != 0 );
			if ( bOverfull ) {
				std::cout << "Overfull in extended eucklid algorithm in bnTemp calculation (Y branch)\n";
				print(bnTemp, 2*num); std::cout<< std::endl;
				print(bnY1, num); std::cout<< std::endl;
				print(bnQ, num); std::cout<< std::endl;
			}
#endif
			add( bnTemp, bnY2, bnTemp, num);
			assign( bnY2, bnY1, num );
			assign( bnY1, bnTemp, num );
		}

	}
	if ( bnGCD != NULL )
		assign( bnGCD, bnA1, num );
	if ( bnX != NULL )
		assign( bnX, bnX2, num );

	if ( bnY != NULL )
		assign( bnY, bnY2, num);
}
*/


void gcd(DIGIT bnGCD[], const DIGIT bnA[], const DIGIT bnB[], DIGIT bnX[], DIGIT bnY[], bool &bXNegative, bool &bYNegative, const unsigned num ){
	bXNegative = false;
	bYNegative = true;

	DIGIT *bnX1 = new DIGIT[2*num];
	DIGIT *bnX2 = new DIGIT[2*num];
	DIGIT *bnY1 = new DIGIT[2*num]; 
	DIGIT *bnY2 = new DIGIT[2*num];
	DIGIT *bnA1 = new DIGIT[2*num];
	DIGIT *bnB1 = new DIGIT[2*num];
	DIGIT *bnQ = new DIGIT[2*num];
	DIGIT *bnR = new DIGIT[2*num];
	DIGIT *bnTemp = new DIGIT[2*num];
	DIGIT *pbnExchange;
	assign( bnA1, bnA, num );
	assign( bnB1, bnB, num );
	if (bnX != NULL ){
		assignDigit( bnX2, 1, num );
		zero( bnX1, num );	
	}
	if ( bnY != NULL ){
		assignDigit( bnY1, 1, num );
		zero( bnY2, num );
	}

	while ( !isZero( bnB1, num )) {
		bXNegative = !bXNegative;
		bYNegative = !bYNegative;

		div( bnA1, bnB1, bnQ, bnR, num, num );
#ifdef _DEBUG_GCD
		static int count =0;
		count++;
		std::cout << count << std::endl;
		std::cout << "bnX1:\t" << bnX1 << std::endl;
		std::cout << "bnX2:\t" << bnX2 << std::endl;
		std::cout << "bnQ:\t" << bnQ << std::endl;
		std::cout << "bnR:\t" << bnR << std::endl;
		std::cout << "bnA1:\t" << bnA1 << std::endl;
		std::cout << "bnB1:\t" << bnB1 << std::endl;
#endif
		pbnExchange = bnA1;
		bnA1 = bnB1;
		bnB1 = bnR;
		bnR = pbnExchange;
		if ( bnX != NULL ){
			
			mul( bnTemp, bnX1, bnQ, num );
#ifdef _VERBOSE_CHECKING
			bool bOverfull = false;
			for (unsigned i=num; i< 2*num; i++)
				bOverfull = bOverfull || (bnTemp[i] != 0 );
			if ( bOverfull ){
#ifdef _DEBUG_GCD
				std::cout << "bnX1:\t" << bnX1 << std::endl;
				std::cout << "bnX2:\t" << bnX2 << std::endl;
				std::cout << "bnA1:\t" << bnA1 << std::endl;
				std::cout << "bnB1:\t" << bnB1 << std::endl;
#endif
				std::cout << "Overfull in extended eucklid algorithm in bnTemp calculation (X branch)\n";
				print(bnTemp, 2*num); std::cout<< std::endl;
				print(bnX1, num); std::cout<< std::endl;
				print(bnQ, num); std::cout<< std::endl;
			}
#endif
			add( bnTemp, bnX2, bnTemp, num);
			pbnExchange = bnX2;
			bnX2 = bnX1;
			bnX1 = bnTemp;
			bnTemp = pbnExchange;
		}
		
		if ( bnY != NULL ){
			mul( bnTemp, bnY1, bnQ, num );
#ifdef _VERBOSE_CHECKING
			bool bOverfull = false;
			for (unsigned i=num; i< 2*num; i++)
				bOverfull = bOverfull || (bnTemp[i] != 0 );
			if ( bOverfull ) {
				std::cout << "Overfull in extended eucklid algorithm in bnTemp calculation (Y branch)\n";
				print(bnTemp, 2*num); std::cout<< std::endl;
				print(bnY1, num); std::cout<< std::endl;
				print(bnQ, num); std::cout<< std::endl;
			}
#endif
			add( bnTemp, bnY2, bnTemp, num);
			pbnExchange = bnY2;
			bnY2 = bnY1;
			bnY1 = bnTemp;
			bnTemp = pbnExchange;
		}

	}
	//if (bOverfull)
	//	std::cout << "Overfull in extended eucklid algorithm in bnTemp\n";
	if ( bnGCD != NULL )
		assign( bnGCD, bnA1, num );
	if ( bnX != NULL )
		assign( bnX, bnX2, num );
	if ( bnY != NULL )
		assign( bnY, bnY2, num);
	delete[] bnX1;
	delete[] bnX2;
	delete[] bnY1; 
	delete[] bnY2;
	delete[] bnA1;
	delete[] bnB1;
	delete[] bnQ;
	delete[] bnR;
	delete[] bnTemp;

}
/*
#define _DEBUG_GCD
#define _VERBOSE_CHECKING
void gcd(DIGIT bnGCD[], const DIGIT bnA[], const DIGIT bnB[], DIGIT bnX[], DIGIT bnY[], bool &bXNegative, bool &bYNegative, const unsigned num ){
	DIGIT *bnG = new DIGIT[2*num];
	bXNegative = false;
	bYNegative = true;
	DIGIT *bnX1 = new DIGIT[num];
	DIGIT *bnX2 = new DIGIT[num];
	DIGIT *bnY1 = new DIGIT[num]; 
	DIGIT *bnY2 = new DIGIT[num];
	DIGIT *bnA1 = new DIGIT[num];
	DIGIT *bnB1 = new DIGIT[num];
	DIGIT *bnU = new DIGIT[num];
	DIGIT *bnV = new DIGIT[num];
	DIGIT *bnTemp = new DIGIT[num+1];
	assign( bnA1, bnA, num );
	assign( bnB1, bnB, num );
	assignDigit( bnG, 1, 2*num );
	while ( isEven(bnA1, num) && isEven (bnB1, num) ){
		shortDiv( bnA1, bnA1, 2, NULL, num );
		shortDiv( bnB1, bnB1, 2, NULL, num );
		shortMul( bnG, bnG, 2, num );
	}

	assign( bnU, bnA1, num );
	assign( bnV, bnB1, num );
	
	assignDigit( bnX2, 1, num );
	zero( bnX1, num );	

	assignDigit( bnY1, 1, num );
	zero( bnY2, num );

	while ( !isEven( bnU, num )) {
		shortDiv( bnU, bnU, 2, NULL, num );
		if ( isEven(bnX1, num) && isEven(bnX2, num) ){
			shortDiv( bnX1, bnX1, 2, NULL, num );
			shortDiv( bnX2, bnX2, 2, NULL, num );
		} else {
			DIGIT res;
			if ( bX2Negative ){
				res = sub( bnX2, bnB1, bnX2,num );
#ifdef _VERBOSE_CHECKING
				if (res > 0)
					std::cout << "gcd(binary): unexpected borrow, means bnX2 > bnB1" << std::endl;
#endif
			} else {
				res = add( bnX2, bnB1, bnX2,num );
			}
			shortDiv( bnX2, bnX2, 2, NULL, num );
			bnX2[num] |= res << ( baseDigits -1 );

			if ( bX1Negative ){
				res = add( bnX1, bnX1, bnA1, num );
			} else {
				if ( 
				res = sub( bnX1, bnA1, bnX1,num );
#ifdef _VERBOSE_CHECKING
				if ( res > 0 )
					std::cout << "Extended binary Euclid algorithm: something wrong -  bnX1 > bnA1" << std::endl;
#endif
			}
			shortDiv( bnX1, bnX1, 2, NULL, num );
			bnX2[num] |= res << ( baseDigits -1 );
		}
	}
	while ( isEven(bnV, num) ){
		
		shortDiv( bnV, bnV, 2, NULL, num );
		if ( isEven(bnY1, num) && isEven(bnY2, num) ){
			shortDiv( bnY2, bnY2, 2, NULL, num );
			shortDiv( bnY1, bnY1, 2, NULL, num );
		} else {
			
			DIGIT overflow = add( bnY2, bnY2, bnB1,num );
#ifdef _DEBUG_GCD
			if (overflow > 0 )
				std::cout << "Binary Euclid alg: overflow in bnX2" << std::endl;
#endif			
			if ( overflow > 0 )
				bnY2[num] = overflow;
			else
				bnY2[num] = 0;
			shortDiv( bnY2, bnY2, 2, NULL, num+1 );

			DIGIT borrow = sub( bnY1, bnY1, bnA1, num );
#ifdef _VERBOSE_CHECKING
			if ( borrow == 0 )
				std::cout << "Extended binary Euclid algorithm: something wrong -  bnY1 > x" << std::endl;
#endif
			shortDiv( bnY1, bnY1, 2, NULL, num );
		}
	}
	if ( bncmp( bnU, bnV, num ) >=0 ){
		sub( bnU, bnU, bnV, num );
		sub( bnX2, bnX2, bnY2, num );
		sub( bnX1, bnX1, bnY1, num );
	} else {
		sub( bnV, bnV, bnU, num );
		DIGIT borrow = sub( bnY2, bnY2, bnX2, num );
		if ( borrow > 0 )
			bXNegative = !bXNegative;
		borrow = sub( bnY1, bnY1, bnX1, num );
		if ( borrow > 0 )
			bYNegative = !bYNegative;
	}



	//if (bOverfull)
	//	std::cout << "Overfull in extended eucklid algorithm in bnTemp\n";
	if ( bnGCD != NULL )
		mul( bnGCD, bnG, bnV, num );
	if ( bnX != NULL )
		assign( bnX, bnY2, num );
	if ( bnY != NULL )
		assign( bnY, bnY1, num);
	delete[] bnX1;
	delete[] bnX2;
	delete[] bnY1; 
	delete[] bnY2;
	delete[] bnA1;
	delete[] bnB1;
	delete[] bnU;
	delete[] bnV;
	delete[] bnG;
	delete[] bnTemp;

}
*/

// деление двух длинных чисел по модулю:
//		res = bn1/bn2 (mod bnMod);
// возвращает:
//		<ничего>
void moddiv( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num ){
	DIGIT bnInvert[MAX_SIZE];
	modInvert( bnInvert, bn2, bnMod, num ) ;
	modmul( res, bn1, bnInvert, bnMod, num );
}

// вычисление мультипликативного обратного элемента в поле классов вычетов (по модулю):
//		bnInvert = bnA^{-1} (mod bnMod) = 1/bnA (mod bnMod);
// входные параметры:
//		bnA			- большое число длины num
//		bnMod		- модуль по которому вычисляется обратное
//		num			- длина больших чисел (unsigned)
// выходные параметры:
//		bnInvert	- большое число, мультипликативное обратное bnA по модулю bnMod
// возвращает:
//		<ничего>
void modInvert(DIGIT bnInvert[], const DIGIT bnA[], const DIGIT bnMod[], const unsigned num ){
	bool bXNegative, bYNegative;
	gcd( NULL, bnA, bnMod, bnInvert, NULL, bXNegative, bYNegative, MAX_SIZE );
	if (bXNegative)
		sub( bnInvert, bnMod, bnInvert, MAX_SIZE );
}


