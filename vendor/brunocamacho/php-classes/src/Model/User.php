<?php

namespace BrunoCamacho\Model;
use BrunoCamacho\DB\Sql;
use BrunoCamacho\Model;
use BrunoCamacho\Mailer;

class User extends Model{
    
    const SESSION = "User";
    const SECRET = "HCodePhp7_Secret";
    const SECRET_IV = "HcodePhp7_Secret_IV";
    
    public static function login($login,$password){
        $sql = new Sql;
        $results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :LOGIN", array(
            ":LOGIN"=>$login
        ));
        
        if(count($results)===0){
            throw new \Exception("Usuário não encontrado ou senha inválida.");
        }
        
        $data = $results[0];
        
        if(password_verify($password, $data["despassword"])===true){
            $user = new User();
            $user->setData($data);
            
            $_SESSION[User::SESSION] = $user->getValues();
            
            return $user;
        }else{
            throw new \Exception("Usuário não encontrado ou senha inválida.");
        }
    }
    
    public static function verifyLogin($inadmin=true){
        
        if(!isset($_SESSION[User::SESSION]) ||
        !$_SESSION[User::SESSION] ||
        !(int)$_SESSION[User::SESSION]["iduser"] > 0 ||
        (bool)$_SESSION[User::SESSION]["inadmin"] !== $inadmin){
            
            header("Location: /admin/login");
            exit;
            
        }
        
    }
    
    public static function logout(){
        $_SESSION[User::SESSION] = NULL;
        
    }
    
    public static function listAll(){
        $sql = new Sql;
        return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
        
    }
    
    public function save(){
        $sql = new Sql();
        $res = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)",array(
        ":desperson"=>$this->getdesperson(),
        ":deslogin"=>$this->getdeslogin(),
        ":despassword"=>$this->getdespassword(),
        ":desemail"=>$this->getdesemail(),
        ":nrphone"=>$this->getnrphone(),
        ":inadmin"=>$this->getinadmin()
        ));
        $this->setData($res[0]);
    }
    
    public function get($iduser){
        $sql = new Sql();
        $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :iduser", array(
                ":iduser"=>$iduser
        ));
        $data = $results[0];
        $data['desperson'] = utf8_encode($data['desperson']);
        $this->setData($data);
        
    }
    
    public function update(){
        $sql = new Sql();
        $res = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)",array(
        ":iduser"=>(int)$this->getiduser(),    
        ":desperson"=>$this->getdesperson(),
        ":deslogin"=>$this->getdeslogin(),
        ":despassword"=>$this->getdespassword(),
        ":desemail"=>$this->getdesemail(),
        ":nrphone"=>$this->getnrphone(),
        ":inadmin"=>$this->getinadmin()
        ));
        
        
        
        $this->setData($res[0]);
        
     
    }
    
    public function delete(){
        
        $sql = new Sql();
        
        $sql->query("CALL sp_users_delete(:iduser)", array(":iduser"=> $this->getiduser()));
        
    }
    
    public static function getForgot($email){
        
        $sql = new Sql();
        
        $res = $sql->select("SELECT * FROM tb_persons a INNER JOIN tb_users b USING(idperson) WHERE a.desemail = :email ;",
                array(":email"=>$email));
        
        if(count($res)===0){
            throw new \Exception("Não foi possível recuperar a senha");
        } else{
            $data = $res[0];
            $res2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", array(
                ":iduser"=>$data['iduser'],
                ":desip"=>$_SERVER["REMOTE_ADDR"]
            ));
            
            if(count($res2)===0){
                throw new \Exception("Não foi possível recuperar a senha");
                
            }else{
                $dataRecovery = $res2[0];
                
                $code = openssl_encrypt($dataRecovery['idrecovery'], 'AES-128-CBC', pack("a16",User::SECRET), 0, pack("a16", User::SECRET_IV));
                $code = base64_encode($code);
                
                $link = "http://viniliza.tk/admin/forgot/reset?code=$code";
                
                $mailer = new Mailer($data['desemail'], $data['desperson'], "Redefinir senha da Bruno's Store", "forgot", array(
                    "name"=>$data['desperson'],
                    "link"=>$link
                ));
                
                $mailer->send();
                return $data;
            }
        }
        
    }
    
    public static function validForgotDecrypt($code){
        
        $code = base64_decode($code);
        
        $id_recovery = openssl_decrypt($code, 'AES-128-CBC', pack("a16",User::SECRET), 0, pack("a16", User::SECRET_IV));
        
        $sql = new Sql();
        
        $res = $sql->select("SELECT *
                FROM tb_userspasswordsrecoveries a
                INNER JOIN tb_users b USING(iduser)
                INNER JOIN tb_persons c USING(idperson)
                WHERE
                    a.idrecovery = :idrecovery
                    AND
                    a.dtrecovery IS NULL
                    AND
                    DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW();", array(":idrecovery"=>$id_recovery));
        
        if(count($res)===0){
            throw new \Exception("Não foi possível recuperar a senha");
        }else{
            return $res[0];
        }
    }
    
    public static function setForgotUsed($idrecover){
        
        $sql = new Sql;
        
        $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(":idrecovery"=>$idrecover));
        
    }
    
    public function setPassword($pass){
        $sql = new Sql;
        $sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
            ":password"=>$pass,
            ":iduser"=>$this->getiduser()
        ));
    }
}
