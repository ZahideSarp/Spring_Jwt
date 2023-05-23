package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {


    //Bu classta basic te  2 sey yapacagız ;
    //1- Jwt token'i genereta edecegiz
    //2- Jwt tokeni valide edecegiz
    //jwt tokeni generate ederken 2 seye ihitiyacımız vardı 1-secret key 2- kullanıcıdan alacagım bir bilgi
    //


    private String jwtSecret = "sboot";//secretKey

    private long jwtExpirationMs = 86400000;   // 24*60*60*1000 ( 1 gun )//mili saniye cinsinden deger alıyor.

    // !!! ********* GENERATE JWT TOKEN *************

   public String generateToken(Authentication authentication){//sistemde login işleminden sonra valide edilen bir
       // kullanıcıya bu class üzerinden ulaşabiliyorum
       // anlik olarak login islemini gerceklestiren kullanici bilgisine ulastik :
       UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
       //getPrincipal() methodu bizim security contex'e atmış oldugumuz anlık olarak login olan kullanıcıyı bizim önümüze getiriyor

       //!!! JWT TOKEN :jwt tokeni userNAme field'i, jwtSecret ve jwtExpirationMs bilgilerini kullanarak olusturuyoruz
       return Jwts.builder().
               setSubject(userDetails.getUsername()).//kullanıcının hangi bilgisini jwt tokene dahil edeceksem onu setledim.
               setIssuedAt(new Date()).//ne zaman uretilecek kendi belirleyecek ama tarih oldugunu soyluyorum.
               setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).//expriration suresini veriyorum  kac gun olacagını veriyorum
               signWith(SignatureAlgorithm.HS512, jwtSecret).//sifreleme -->H algoritması ile şifrelenmesini istiyorum
               compact();//yapıyı bohcalıyorum

   }


    // !!! ********* VALIDATE JWT TOKEN **************
    //eger bir kullanıcı valide edilmişsse authendice edilmiş demektir.

    public boolean validateToken(String token){

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            //parcer(): vaalidasyon işlemi için kullandıgım method 2 sey istiyor
            //1-secret key istiyor 2- tokenin kendisini istiyor.Bu iki bilgiyi verirsek method chance seklinde
            //bize otomatikman jwt tokenin dogru token olup olmadıgını valide edip boolean olarak gonderiyor.
            return true;//excp. fırlamazsa valide edilmiştir diyoruz
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false ;

    }


    // !!! ********* GET UserName FROm JWT TOKEN **********
    public String getUserNameFromJwtToken(String token){
       return Jwts.parser().
               setSigningKey(jwtSecret).
               parseClaimsJws(token).//buraya kadar aynı
               getBody().//body'sine git ve Subject methodunu getir diyorum.
               getSubject();
        //body'sine git ve Subject methodunu getir diyorum.
       //Jwt token generate edilirken setsubject methodu() ile bunu subject kısmına userName bilgisini gondermiştim
    }


}
