<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/quiz-v29.php';
require __DIR__.'/v36-exams.php';
require __DIR__.'/v37-attempts.php';
require __DIR__.'/m1.php';
require __DIR__.'/m2.php';
require __DIR__.'/m3.php';
require __DIR__.'/m4.php';
require __DIR__.'/m5.php';
require __DIR__.'/m7.php';
// Security headers for API JSON responses (no impact on HTML/CSS theme).
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');

try{
 $cfg=academy_config();$origin=$_SERVER['HTTP_ORIGIN']??'';$allowed=$cfg['app']['cors_origins']??[];
 if($origin&&in_array($origin,$allowed,true)){header('Access-Control-Allow-Origin: '.$origin);header('Vary: Origin');header('Access-Control-Allow-Headers: Content-Type, Authorization');header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');}
 $method=$_SERVER['REQUEST_METHOD']??'GET';if($method==='OPTIONS'){http_response_code(204);exit;}
 $uri=parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH)?:'/';$pos=strpos($uri,'/api');$route='/'.trim($pos===false?$uri:substr($uri,$pos+4),'/');
 $pdo=academy_db();
 academy_m1_route($route,$method,$pdo);
 academy_m2_route($route,$method,$pdo);
 academy_m3_route($route,$method,$pdo);
 academy_m4_route($route,$method,$pdo);
 academy_m5_route($route,$method,$pdo);
 academy_m7_route($route,$method,$pdo);

 if($route==='/health'&&$method==='GET')academy_json(['ok'=>true,'service'=>'academy-hostinger-api','version'=>ACADEMY_API_VERSION,'database'=>'connected','time'=>gmdate('c')]);

 if($route==='/setup/status'&&$method==='GET'){
   $count=(int)$pdo->query("SELECT COUNT(*) FROM academy_users WHERE primary_role='admin'")->fetchColumn();academy_json(['ok'=>true,'needsAdmin'=>$count===0]);
 }
 if($route==='/setup/admin'&&$method==='POST'){
   academy_rate_limit('first-admin',10,3600);
   $setupLock='academy:setup:first-admin';
   if((int)$pdo->query('SELECT GET_LOCK('.$pdo->quote($setupLock).',5)')->fetchColumn()!==1)academy_json(['ok'=>false,'error'=>'busy'],409);
   $count=(int)$pdo->query("SELECT COUNT(*) FROM academy_users WHERE primary_role='admin'")->fetchColumn();
   if($count>0){$pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($setupLock).')');academy_json(['ok'=>false,'error'=>'setup_closed'],403);}
   $b=academy_body();$email=strtolower(trim((string)($b['email']??'')));$password=(string)($b['password']??'');$name=trim((string)($b['displayName']??'مدير الأكاديمية'));
   if(!filter_var($email,FILTER_VALIDATE_EMAIL))academy_json(['ok'=>false,'error'=>'invalid_email'],422);if(!academy_password_valid($password))academy_json(['ok'=>false,'error'=>'weak_password'],422);if($name===''||mb_strlen($name)>190)academy_json(['ok'=>false,'error'=>'display_name_required'],422);
   $id=academy_uuid();$pdo->beginTransaction();try{$pdo->prepare("INSERT INTO academy_users(id,email,password_hash,display_name,primary_role,status,email_verified) VALUES(?,?,?,?, 'admin','active',1)")->execute([$id,$email,password_hash($password,PASSWORD_DEFAULT),$name]);academy_delete_node_raw($pdo,'adminProfiles/'.$id);academy_insert_value_raw($pdo,'adminProfiles/'.$id,['isAdmin'=>true,'name'=>$name,'email'=>$email,'createdAt'=>(int)round(microtime(true)*1000)],$id);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
   $pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($setupLock).')');academy_audit($id,'setup.first_admin');academy_json(['ok'=>true,'user'=>['uid'=>$id,'email'=>$email,'displayName'=>$name,'role'=>'admin']],201);
 }

 if($route==='/auth/register'&&$method==='POST'){
   academy_rate_limit('register',12,3600);$b=academy_body();$email=strtolower(trim((string)($b['email']??'')));$password=(string)($b['password']??'');$name=trim((string)($b['displayName']??''));$app=substr((string)($b['appName']??'[DEFAULT]'),0,64);$role=academy_expected_role($app);
   if(!in_array($role,['student','parent'],true))academy_json(['ok'=>false,'error'=>'registration_not_allowed'],403);if(!filter_var($email,FILTER_VALIDATE_EMAIL))academy_json(['ok'=>false,'error'=>'invalid_email'],422);if(!academy_password_valid($password))academy_json(['ok'=>false,'error'=>'weak_password'],422);
   $id=academy_uuid();try{$pdo->prepare('INSERT INTO academy_users(id,email,password_hash,display_name,primary_role,status) VALUES(?,?,?,?,?,\'active\')')->execute([$id,$email,password_hash($password,PASSWORD_DEFAULT),$name,$role]);}catch(PDOException$e){if((string)$e->getCode()==='23000')academy_json(['ok'=>false,'error'=>'email_exists'],409);throw$e;}
   $token=academy_token();$days=max(1,(int)($cfg['app']['session_days']??30));$expires=gmdate('Y-m-d H:i:s',time()+$days*86400);$pdo->prepare('INSERT INTO academy_sessions(user_id,app_name,token_hash,user_agent_hash,expires_at) VALUES(?,?,?,?,?)')->execute([$id,$app,academy_token_hash($token),academy_user_agent_hash(),$expires]);academy_audit($id,'auth.register',null,['role'=>$role]);academy_json(['ok'=>true,'token'=>$token,'user'=>['uid'=>$id,'email'=>$email,'displayName'=>$name,'role'=>$role]],201);
 }
 if($route==='/auth/login'&&$method==='POST'){
   academy_rate_limit('login',25,900);$b=academy_body();$email=strtolower(trim((string)($b['email']??'')));academy_rate_limit('login-account-'.hash('sha256',$email),12,900);$password=(string)($b['password']??'');$app=substr((string)($b['appName']??'[DEFAULT]'),0,64);$expected=academy_expected_role($app);
   $st=$pdo->prepare('SELECT * FROM academy_users WHERE email=? LIMIT 1');$st->execute([$email]);$u=$st->fetch();if(!$u||!password_verify($password,$u['password_hash']))academy_json(['ok'=>false,'error'=>'invalid_credentials'],401);if($u['status']!=='active')academy_json(['ok'=>false,'error'=>$u['status']==='pending'?'account_pending':'account_disabled'],403);if($expected&&$u['primary_role']!==$expected)academy_json(['ok'=>false,'error'=>'invalid_credentials'],401);
   $token=academy_token();$days=max(1,(int)($cfg['app']['session_days']??30));$expires=gmdate('Y-m-d H:i:s',time()+$days*86400);$pdo->prepare('INSERT INTO academy_sessions(user_id,app_name,token_hash,user_agent_hash,expires_at) VALUES(?,?,?,?,?)')->execute([$u['id'],$app,academy_token_hash($token),academy_user_agent_hash(),$expires]);$pdo->prepare('UPDATE academy_users SET last_login_at=UTC_TIMESTAMP() WHERE id=?')->execute([$u['id']]);academy_audit($u['id'],'auth.login',null,['appName'=>$app]);academy_json(['ok'=>true,'token'=>$token,'user'=>['uid'=>$u['id'],'email'=>$u['email'],'displayName'=>$u['display_name'],'role'=>$u['primary_role']]]);
 }
 if($route==='/auth/me'&&$method==='GET'){$u=academy_current_user(true);academy_json(['ok'=>true,'user'=>['uid'=>$u['id'],'email'=>$u['email'],'displayName'=>$u['display_name'],'role'=>$u['primary_role'],'appName'=>$u['app_name']]]);}
 if($route==='/auth/logout'&&$method==='POST'){$u=academy_current_user(false);$t=academy_bearer();if($t)$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=?')->execute([academy_token_hash($t)]);if($u)academy_audit($u['id'],'auth.logout');academy_json(['ok'=>true]);}
 if($route==='/auth/profile'&&$method==='PATCH'){$u=academy_current_user(true);$b=academy_body();$name=trim((string)($b['displayName']??''));if($name===''||mb_strlen($name)>190)academy_json(['ok'=>false,'error'=>'display_name_required'],422);$pdo->prepare('UPDATE academy_users SET display_name=? WHERE id=?')->execute([$name,$u['id']]);academy_audit($u['id'],'auth.profile.update');academy_json(['ok'=>true,'user'=>['uid'=>$u['id'],'email'=>$u['email'],'displayName'=>$name,'role'=>$u['primary_role']]]);}
 if($route==='/auth/reauth'&&$method==='POST'){$u=academy_current_user(true);academy_rate_limit('reauth-'.$u['id'],6,900);$b=academy_body();$st=$pdo->prepare('SELECT password_hash FROM academy_users WHERE id=?');$st->execute([$u['id']]);if(!password_verify((string)($b['password']??''),(string)$st->fetchColumn()))academy_json(['ok'=>false,'error'=>'wrong_password'],401);academy_json(['ok'=>true]);}
 if($route==='/auth/password'&&$method==='PATCH'){$u=academy_current_user(true);$b=academy_body();$old=(string)($b['oldPassword']??'');$new=(string)($b['newPassword']??'');$st=$pdo->prepare('SELECT password_hash FROM academy_users WHERE id=?');$st->execute([$u['id']]);if(!password_verify($old,(string)$st->fetchColumn()))academy_json(['ok'=>false,'error'=>'wrong_password'],401);if(!academy_password_valid($new))academy_json(['ok'=>false,'error'=>'weak_password'],422);$pdo->prepare('UPDATE academy_users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),$u['id']]);$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE user_id=? AND token_hash<>?')->execute([$u['id'],academy_token_hash(academy_bearer()??'')]);academy_audit($u['id'],'auth.password.change');academy_json(['ok'=>true]);}
 if($route==='/auth/password-reset-request'&&$method==='POST'){
   academy_rate_limit('password-reset',8,3600);$b=academy_body();$email=strtolower(trim((string)($b['email']??'')));$st=$pdo->prepare('SELECT id,email FROM academy_users WHERE email=? AND status=\'active\' LIMIT 1');$st->execute([$email]);$u=$st->fetch();if($u&&filter_var($email,FILTER_VALIDATE_EMAIL)&&!str_ends_with($email,'.invalid')){$raw=academy_token();$pdo->prepare('INSERT INTO academy_password_resets(user_id,token_hash,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR))')->execute([$u['id'],academy_token_hash($raw)]);$base=rtrim((string)($cfg['app']['base_url']??''),'/');if($base===''||$base==='auto'){$scheme=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';$prefix=$pos===false?'':substr($uri,0,$pos);$host=(string)($_SERVER['SERVER_NAME']??'');if(!preg_match('/^[a-z0-9.-]+$/iD',$host)||$host==='')academy_json(['ok'=>false,'error'=>'server_misconfigured'],500);$base=$scheme.'://'.$host.$prefix;}$link=$base.'/reset-password.html?token='.rawurlencode($raw);$from=(string)($cfg['app']['mail_from']??'');if(!filter_var($from,FILTER_VALIDATE_EMAIL))$from='no-reply@egtaz.online';@mail($email,'Academy password reset',"Open this link within one hour:\n$link","From: $from\r\nContent-Type: text/plain; charset=UTF-8");}academy_json(['ok'=>true]);
 }
 if($route==='/auth/password-reset'&&$method==='POST'){$b=academy_body();academy_rate_limit('password-reset-submit',10,900);$raw=(string)($b['token']??'');$new=(string)($b['newPassword']??'');if(strlen($raw)>256||strlen($raw)<20)academy_json(['ok'=>false,'error'=>'invalid_reset_token'],400);if(!academy_password_valid($new))academy_json(['ok'=>false,'error'=>'weak_password'],422);$st=$pdo->prepare('SELECT id,user_id FROM academy_password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>UTC_TIMESTAMP() LIMIT 1');$st->execute([academy_token_hash($raw)]);$r=$st->fetch();if(!$r)academy_json(['ok'=>false,'error'=>'invalid_reset_token'],400);$pdo->beginTransaction();try{$claimed=$pdo->prepare('UPDATE academy_password_resets SET used_at=UTC_TIMESTAMP() WHERE id=? AND used_at IS NULL AND expires_at>UTC_TIMESTAMP()');$claimed->execute([$r['id']]);if($claimed->rowCount()!==1){$pdo->rollBack();academy_json(['ok'=>false,'error'=>'invalid_reset_token'],400);}$pdo->prepare('UPDATE academy_users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),$r['user_id']]);$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE user_id=?')->execute([$r['user_id']]);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}academy_audit($r['user_id'],'auth.password.reset');academy_json(['ok'=>true]);}

 if($route==='/admin/users'&&$method==='POST'){$admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$email=strtolower(trim((string)($b['email']??'')));$password=(string)($b['password']??'');$name=trim((string)($b['displayName']??''));$role=(string)($b['role']??'teacher');if(!in_array($role,['teacher','parent','student'],true)||!filter_var($email,FILTER_VALIDATE_EMAIL)||!academy_password_valid($password))academy_json(['ok'=>false,'error'=>'invalid_user'],422);$id=academy_uuid();try{$pdo->prepare('INSERT INTO academy_users(id,email,password_hash,display_name,primary_role,status) VALUES(?,?,?,?,?,\'active\')')->execute([$id,$email,password_hash($password,PASSWORD_DEFAULT),$name,$role]);}catch(PDOException$e){if((string)$e->getCode()==='23000')academy_json(['ok'=>false,'error'=>'email_exists'],409);throw$e;}academy_audit($admin['id'],'admin.user.create',$id,['role'=>$role]);academy_json(['ok'=>true,'user'=>['uid'=>$id,'email'=>$email,'displayName'=>$name,'role'=>$role]],201);}
 if($route==='/admin/users/password'&&$method==='POST'){$admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=(string)($b['uid']??'');$new=(string)($b['newPassword']??$b['password']??'');if(!academy_password_valid($new))academy_json(['ok'=>false,'error'=>'weak_password'],422);$pdo->prepare('UPDATE academy_users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),$uid]);$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE user_id=?')->execute([$uid]);academy_audit($admin['id'],'admin.user.password_reset',$uid);academy_json(['ok'=>true]);}
 if($route==='/admin/users/access'&&$method==='POST'){$admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=trim((string)($b['uid']??''));$role=array_key_exists('role',$b)?(string)$b['role']:null;$status=array_key_exists('status',$b)?(string)$b['status']:null;if($uid===''||$uid===$admin['id'])academy_json(['ok'=>false,'error'=>'invalid_user'],422);if($role!==null&&!in_array($role,['student','teacher','parent'],true))academy_json(['ok'=>false,'error'=>'invalid_role'],422);if($status!==null&&!in_array($status,['active','pending','suspended','disabled'],true))academy_json(['ok'=>false,'error'=>'invalid_status'],422);if($role===null&&$status===null)academy_json(['ok'=>false,'error'=>'no_changes'],422);$st=$pdo->prepare('SELECT id,primary_role,status FROM academy_users WHERE id=? LIMIT 1');$st->execute([$uid]);$target=$st->fetch();if(!$target)academy_json(['ok'=>false,'error'=>'user_not_found'],404);$sets=[];$args=[];if($role!==null){$sets[]='primary_role=?';$args[]=$role;}if($status!==null){$sets[]='status=?';$args[]=$status;}$args[]=$uid;$pdo->prepare('UPDATE academy_users SET '.implode(',',$sets).' WHERE id=?')->execute($args);if($role!==null||($status!==null&&$status!=='active'))$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE user_id=?')->execute([$uid]);academy_audit($admin['id'],'admin.user.access',$uid,['role'=>$role,'status'=>$status]);academy_json(['ok'=>true,'user'=>['uid'=>$uid,'role'=>$role??$target['primary_role'],'status'=>$status??$target['status']]]);}


 // ---- V5 secure product endpoints -------------------------------------------------
 if($route==='/events/audit'&&$method==='POST'){
   $u=academy_current_user(true);$b=academy_body();$action=substr(trim((string)($b['action']??'')),0,100);$entity=substr(trim((string)($b['entity']??'')),0,80);$entityId=substr(trim((string)($b['entityId']??'')),0,180);$meta=is_array($b['meta']??null)?$b['meta']:[];if($action==='')academy_json(['ok'=>false,'error'=>'action_required'],422);academy_audit($u['id'],'client.'.substr($action,0,93),$entity!==''?($entity.($entityId!==''?'/'.$entityId:'')):null,array_slice($meta,0,30,true));academy_json(['ok'=>true]);
 }
 if($route==='/student/profile/phone-index'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();
   $profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($profile))$profile=[];
   $phone=trim((string)($b['phone']??($profile['phone']??'')));$name=trim((string)($b['name']??($profile['name']??$u['display_name']??'')));
   $digits=preg_replace('/\D+/','',$phone);if($digits==='')academy_json(['ok'=>false,'error'=>'phone_required'],422);$ts=academy_now_ms();
   $updates=['studentPhoneIndexV4/'.$digits=>['studentId'=>$u['id'],'updatedAt'=>$ts],'phoneDirectoryV4/students/'.$u['id']=>['uid'=>$u['id'],'name'=>$name,'phone'=>$phone,'updatedAt'=>$ts]];
   $pdo->beginTransaction();try{foreach($updates as$p=>$v){academy_delete_node_raw($pdo,$p);academy_insert_value_raw($pdo,$p,$v,$u['id']);}$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
   academy_audit($u['id'],'student.phone_index.sync','studentProfilesV3/'.$u['id']);academy_json(['ok'=>true]);
 }
 if($route==='/parent/invite'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);academy_rate_limit('parent-invite-'.$u['id'],10,3600);$code='';do{$code=strtoupper(substr(bin2hex(random_bytes(5)),0,8));}while(academy_read_node('parentInvitesV4/'.$code)!==null);$ts=academy_now_ms();
   academy_write_node('parentInvitesV4/'.$code,['studentId'=>$u['id'],'createdAt'=>$ts,'expiresAt'=>$ts+7*86400000,'used'=>false],$u['id']);academy_audit($u['id'],'parent.invite.create',$code);academy_json(['ok'=>true,'code'=>$code,'expiresAt'=>$ts+7*86400000]);
 }
 if($route==='/parent/link/code'&&$method==='POST'){
   $u=academy_current_user(true);
   if($u['primary_role']!=='parent')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   academy_rate_limit('parent-link-code-'.$u['id'],20,3600);
   $b=academy_body();$code=strtoupper(trim((string)($b['code']??'')));
   if(!preg_match('/^[A-F0-9]{8}$/D',$code))academy_json(['ok'=>false,'error'=>'invalid_invite'],422);
   // Serialize claiming a one-time invite, so concurrent requests cannot link two parents.
   $locks=academy_acquire_data_locks($pdo,['parentInvitesV4/'.$code,'parentLinksV4/'.$u['id']]);
   $valid=false;$sid='';$ts=academy_now_ms();
   try{
     $invite=academy_read_node('parentInvitesV4/'.$code);
     if(is_array($invite)&&($invite['used']??false)!==true&&($invite['expiresAt']??0)>=$ts){
       $sid=(string)($invite['studentId']??'');
       if($sid!==''){
         $pdo->beginTransaction();
         try{
           academy_delete_node_raw($pdo,'parentLinksV4/'.$u['id'].'/'.$sid);
           academy_insert_value_raw($pdo,'parentLinksV4/'.$u['id'].'/'.$sid,['studentId'=>$sid,'linkedAt'=>$ts,'method'=>'code','inviteCode'=>$code],$u['id']);
           academy_delete_node_raw($pdo,'parentInvitesV4/'.$code);
           academy_insert_value_raw($pdo,'parentInvitesV4/'.$code,array_merge($invite,['used'=>true,'parentId'=>$u['id'],'usedAt'=>$ts]),$u['id']);
           $pdo->commit();$valid=true;
         }catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
       }
     }
   }finally{academy_release_data_locks($pdo,$locks);}
   if(!$valid)academy_json(['ok'=>false,'error'=>'invalid_invite'],422);
   academy_audit($u['id'],'parent.link.code',$sid);academy_json(['ok'=>true,'studentId'=>$sid]);
 }
 // V29/4: a phone number is not proof of a guardian relationship.
 // The parent portal uses /parent/link/code with a one-time student-issued invite.
 if($route==='/parent/link/phone'&&$method==='POST'){
   $u=academy_current_user(true);
   if($u['primary_role']!=='parent')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   academy_json(['ok'=>false,'error'=>'invite_code_required'],403);
 }
 if($route==='/teacher/groups'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$raw=academy_read_node('teacherGroupsV4/'.$u['id']);$rows=[];
   if(is_array($raw))foreach($raw as$id=>$g){if(!is_array($g))continue;$members=$g['members']??[];$g['id']=(string)$id;$g['membersCount']=is_array($members)?count($members):0;unset($g['members']);$rows[]=$g;}
   usort($rows,fn($a,$b)=>(int)($b['createdAt']??0)<=>(int)($a['createdAt']??0));academy_json(['ok'=>true,'groups'=>$rows]);
 }
 if($route==='/teacher/groups/create'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);if((academy_teacher_permissions($u['id'])['createGroups']??true)!==true)academy_json(['ok'=>false,'error'=>'group_permission_required'],403);$b=academy_body();$name=trim((string)($b['name']??''));if(mb_strlen($name)<2)academy_json(['ok'=>false,'error'=>'name_required'],422);
   $scope=['type'=>(string)($b['type']??'public'),'stage'=>(string)($b['stage']??''),'grade'=>(string)($b['grade']??''),'subject'=>(string)($b['subject']??'')];$matched=null;foreach(academy_teacher_assignments($u['id'])as$a){$ok=true;foreach(['type','stage','grade','subject']as$k)if(!empty($a[$k])&&(string)$a[$k]!==$scope[$k])$ok=false;if($ok){$matched=$a;break;}}if(!$matched)academy_json(['ok'=>false,'error'=>'scope_not_assigned'],403);
   $id=substr(str_replace('-','',academy_uuid()),0,20);do{$code='CLS-'.strtoupper(substr(bin2hex(random_bytes(4)),0,6));}while(academy_read_node('groupJoinCodesV1/'.$code)!==null);$ts=academy_now_ms();$group=['id'=>$id,'code'=>$code,'name'=>$name,'description'=>trim((string)($b['description']??'')),'teacherId'=>$u['id'],'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>$scope['grade'],'subject'=>$scope['subject'],'subjectName'=>(string)($matched['subjectName']??$scope['subject']),'active'=>true,'members'=>[],'createdAt'=>$ts,'updatedAt'=>$ts];
   $pdo->beginTransaction();try{academy_delete_node_raw($pdo,'teacherGroupsV4/'.$u['id'].'/'.$id);academy_insert_value_raw($pdo,'teacherGroupsV4/'.$u['id'].'/'.$id,$group,$u['id']);academy_delete_node_raw($pdo,'groupJoinCodesV1/'.$code);academy_insert_value_raw($pdo,'groupJoinCodesV1/'.$code,['teacherId'=>$u['id'],'groupId'=>$id,'active'=>true,'createdAt'=>$ts],$u['id']);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
   academy_audit($u['id'],'teacher.group.create',$id,['code'=>$code]);academy_json(['ok'=>true,'group'=>$group],201);
 }
 if(($route==='/teacher/groups/delete'||$route==='/teacher/groups/status')&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$id=trim((string)($b['id']??''));$group=academy_read_node('teacherGroupsV4/'.$u['id'].'/'.$id);if(!is_array($group))academy_json(['ok'=>false,'error'=>'group_not_found'],404);$code=(string)($group['code']??'');
   if($route==='/teacher/groups/delete'){$pdo->beginTransaction();try{academy_delete_node_raw($pdo,'teacherGroupsV4/'.$u['id'].'/'.$id);if($code!=='')academy_delete_node_raw($pdo,'groupJoinCodesV1/'.$code);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}academy_audit($u['id'],'teacher.group.delete',$id);academy_json(['ok'=>true]);}
   $active=(bool)($b['active']??true);$group['active']=$active;$group['updatedAt']=academy_now_ms();academy_write_node('teacherGroupsV4/'.$u['id'].'/'.$id,$group,$u['id']);if($code!==''){ $idx=academy_read_node('groupJoinCodesV1/'.$code);if(!is_array($idx))$idx=['teacherId'=>$u['id'],'groupId'=>$id];$idx['active']=$active;$idx['updatedAt']=academy_now_ms();academy_write_node('groupJoinCodesV1/'.$code,$idx,$u['id']);}academy_audit($u['id'],'teacher.group.status',$id,['active'=>$active]);academy_json(['ok'=>true]);
 }
 if($route==='/student/groups'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$profile=academy_read_node('studentProfilesV3/'.$u['id']);$ids=[];$raw=is_array($profile)?($profile['groupIds']??[]):[];if(is_array($raw))$ids=array_is_list($raw)?array_map('strval',$raw):array_map('strval',array_keys(array_filter($raw)));
   $all=academy_read_node('teacherGroupsV4');$rows=[];if(is_array($all))foreach($all as$teacherId=>$groups)if(is_array($groups))foreach($groups as$id=>$g)if(in_array((string)$id,$ids,true)&&is_array($g)){$rows[]=['id'=>(string)$id,'teacherId'=>(string)$teacherId,'name'=>$g['name']??'فصل','description'=>$g['description']??'','subject'=>$g['subject']??'','subjectName'=>$g['subjectName']??'','stage'=>$g['stage']??'','grade'=>$g['grade']??'','active'=>$g['active']??true];}
   academy_json(['ok'=>true,'groups'=>$rows]);
 }
 if($route==='/student/groups/join'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$code=strtoupper(trim((string)($b['code']??'')));$idx=academy_read_node('groupJoinCodesV1/'.$code);if(!is_array($idx)||($idx['active']??false)!==true)academy_json(['ok'=>false,'error'=>'invalid_group_code'],404);$teacherId=(string)($idx['teacherId']??'');$groupId=(string)($idx['groupId']??'');$group=academy_read_node('teacherGroupsV4/'.$teacherId.'/'.$groupId);$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($group)||($group['active']??false)!==true||!is_array($profile))academy_json(['ok'=>false,'error'=>'group_unavailable'],404);if(!academy_scope_matches($group,$profile))academy_json(['ok'=>false,'error'=>'group_scope_mismatch'],422);$ts=academy_now_ms();
   $pdo->beginTransaction();try{academy_delete_node_raw($pdo,'studentProfilesV3/'.$u['id'].'/groupIds/'.$groupId);academy_insert_value_raw($pdo,'studentProfilesV3/'.$u['id'].'/groupIds/'.$groupId,true,$u['id']);academy_delete_node_raw($pdo,'teacherGroupsV4/'.$teacherId.'/'.$groupId.'/members/'.$u['id']);academy_insert_value_raw($pdo,'teacherGroupsV4/'.$teacherId.'/'.$groupId.'/members/'.$u['id'],['studentId'=>$u['id'],'name'=>$profile['name']??$u['display_name'],'joinedAt'=>$ts],$u['id']);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
   academy_audit($u['id'],'student.group.join',$groupId,['teacherId'=>$teacherId]);academy_json(['ok'=>true,'group'=>['id'=>$groupId,'name'=>$group['name']??'فصل','subjectName'=>$group['subjectName']??'']]);
 }
 /* V29/2: verified grade submission. Never trust a percentage posted by the browser. */
 if($route==='/student/quiz/submit'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $body=academy_body();$lessonId=trim((string)($body['lessonId']??''));$sourceType=(string)($body['sourceType']??'');$quizId=trim((string)($body['quizId']??''));$teacherId=trim((string)($body['teacherId']??''));$attemptId=trim((string)($body['attemptId']??''));
   if(!preg_match('/^[a-zA-Z0-9_-]{2,120}$/D',$lessonId)||!in_array($sourceType,['teacher','standalone','embedded'],true)||!preg_match('/^[a-zA-Z0-9_-]{2,180}$/D',$quizId)||!preg_match('/^[a-zA-Z0-9_-]{8,80}$/D',$attemptId))academy_json(['ok'=>false,'error'=>'quiz_request_invalid'],422);
   $lesson=academy_read_node('lessons/'.$lessonId);
   if(!is_array($lesson)||($lesson['isHidden']??false)===true||($lesson['workflowStatus']??'')==='draft')academy_json(['ok'=>false,'error'=>'lesson_not_found'],404);
   if(!academy_student_can_access_content($u,$lesson))academy_json(['ok'=>false,'error'=>'content_locked'],403);
   $profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'profile_missing'],422);
   $historyPath='studentProfilesV3/'.$u['id'].'/quizHistory/'.$attemptId;
   // A confirmed retry must return the original result even if the quiz changed meanwhile.
   $saved=academy_read_node($historyPath);
   if(is_array($saved)){
     try{academy_v37_assert_retry($saved,$lessonId,$quizId,$sourceType,$body['answers']??null);}
     catch(InvalidArgumentException $e){academy_json(['ok'=>false,'error'=>'answers_invalid'],422);}
     catch(DomainException $e){academy_json(['ok'=>false,'error'=>'attempt_conflict'],409);}
     academy_json(academy_v37_retry_payload($saved));
   }
   $source=null;$sourceVersion=0;
   if($sourceType==='embedded'){
      if($quizId!=='lesson_'.$lessonId)academy_json(['ok'=>false,'error'=>'quiz_not_found'],404);
      $source=$lesson;$sourceVersion=(int)($lesson['updatedAt']??0);
   }elseif($sourceType==='standalone'){
      $quiz=academy_read_node('quizzes/'.$quizId);
      if(is_array($quiz)&&($quiz['lessonId']??'')===$lessonId&&($quiz['isHidden']??false)!==true&&($quiz['workflowStatus']??'')!=='draft'&&academy_student_can_access_content($u,$quiz)){$source=$quiz;$sourceVersion=(int)($quiz['updatedAt']??0);}
   }else{
      if(!preg_match('/^[a-zA-Z0-9_-]{2,120}$/D',$teacherId)||$quizId!=='teacher_'.$teacherId.'_'.$lessonId)academy_json(['ok'=>false,'error'=>'quiz_not_found'],404);
      $package=academy_read_node('teacherContentsV6/'.$lessonId.'/'.$teacherId);
      if(!is_array($package)){$legacy=academy_legacy_teacher_packages($lessonId,$lesson);$package=$legacy[$teacherId]??null;}
      if(is_array($package)){$safe=academy_public_teacher_package($lessonId,$teacherId,$package,$u,$lesson);if(is_array($safe)&&empty($safe['accessLocked'])&&is_array($safe['quiz']??null)){$source=is_array($package['quiz']??null)?$package['quiz']:$safe['quiz'];$sourceVersion=(int)($source['updatedAt']??0);}}
   }
   $questions=academy_v29_questions($source['questions']??null);
   if(!$questions)academy_json(['ok'=>false,'error'=>'quiz_not_found'],404);
   if(isset($body['sourceVersion'])&&(int)$body['sourceVersion']!==$sourceVersion)academy_json(['ok'=>false,'error'=>'quiz_changed'],409);
   try{$scored=academy_v29_score($questions,$body['answers']??null);}catch(InvalidArgumentException $e){academy_json(['ok'=>false,'error'=>'answers_invalid'],422);}
   $latestPath='studentProfilesV3/'.$u['id'].'/quizResultsV22/'.$quizId;
   $historyPath='studentProfilesV3/'.$u['id'].'/quizHistory/'.$attemptId;
   $lock='academy:quiz-submit:'.hash('sha256',$u['id']);
   $locked=(int)$pdo->query('SELECT GET_LOCK('.$pdo->quote($lock).',5)')->fetchColumn();if($locked!==1)academy_json(['ok'=>false,'error'=>'busy'],409);
   try{
     $existing=academy_read_node($historyPath);
     if(is_array($existing)){
       try{academy_v37_assert_retry($existing,$lessonId,$quizId,$sourceType,$body['answers']??null);}
       catch(InvalidArgumentException $e){academy_json(['ok'=>false,'error'=>'answers_invalid'],422);}
       catch(DomainException $e){academy_json(['ok'=>false,'error'=>'attempt_conflict'],409);}
       academy_json(academy_v37_retry_payload($existing));
     }
     academy_rate_limit('student-quiz-'.$u['id'],80,3600);
     $ts=academy_now_ms();
     $awardPath='learningV4/xpAwardedQuizV36/'.$u['id'].'/'.$quizId;
     $awardSeen=academy_read_node($awardPath)!==null;
     $xpEarned=$awardSeen?0:academy_v36_quiz_xp($scored);
     $previousStats=academy_read_node('studentProfilesV3/'.$u['id'].'/stats');
     if(!is_array($previousStats))$previousStats=[];
     $totalXp=max(0,(int)($previousStats['totalXP']??0))+$xpEarned;
     $ts=academy_now_ms();$result=array_merge($scored,['attemptId'=>$attemptId,'quizId'=>$quizId,'lessonId'=>$lessonId,'title'=>mb_substr(trim((string)($source['title']??$source['name']??'اختبار الدرس')),0,160),'teacherId'=>$teacherId,'sourceType'=>$sourceType,'subject'=>(string)($lesson['subject']??''),'type'=>(string)($lesson['type']??'public'),'stage'=>(string)($lesson['stage']??''),'grade'=>(string)($lesson['grade']??''),'at'=>$ts,'createdAt'=>$ts,'sourceVersion'=>$sourceVersion]);
     // Save the actual answer fingerprint and post-submission review with this attempt.
     // An idempotent retry never calculates its score from a possibly revised quiz.
     $assessmentReview=academy_v36_exam_quiz($source)?academy_v36_exam_review($questions,$body['answers']):null;
     $historyResult=$result;
     $historyResult['answersHash']=academy_v37_answers_hash($body['answers']);
     if($assessmentReview!==null)$historyResult['reviewV37']=$assessmentReview;
     // Keep the latest result and the historical attempt together.
     $pdo->beginTransaction();try{
       academy_delete_node_raw($pdo,$latestPath);academy_insert_value_raw($pdo,$latestPath,$result,$u['id']);
       academy_delete_node_raw($pdo,$historyPath);academy_insert_value_raw($pdo,$historyPath,$historyResult,$u['id']);
       if($xpEarned>0){
         $newStats=$previousStats;
         $newStats['totalXP']=$totalXp;
         $newStats['level']=max(1,intdiv($totalXp,1000)+1);
         $newStats['completedQuizzes']=max(0,(int)($newStats['completedQuizzes']??0))+1;
         academy_delete_node_raw($pdo,'studentProfilesV3/'.$u['id'].'/stats');
         academy_insert_value_raw($pdo,'studentProfilesV3/'.$u['id'].'/stats',$newStats,$u['id']);
         academy_insert_value_raw($pdo,$awardPath,['quizId'=>$quizId,'xp'=>$xpEarned,'at'=>$ts],$u['id']);
       }

       // V32: store incorrect questions derived from the verified server-side answer key.
       // Prior attempts contain only totals, so do not invent their incorrect answers.
       $wrong=[];
       foreach($questions as $i=>$question){
         if($question['correct']===$body['answers'][$i])continue;
         $wrong[]=[
           'question'=>mb_substr((string)$question['question'],0,600),
           'options'=>array_map(static fn($v)=>mb_substr((string)$v,0,300),$question['options']),
           'correct'=>(int)$question['correct'],
           'selected'=>(int)$body['answers'][$i],
         ];
       }
       $mistakePath='studentProfilesV3/'.$u['id'].'/quizMistakesV32/'.$attemptId;
       $mistakes=['attemptId'=>$attemptId,'quizId'=>$quizId,'lessonId'=>$lessonId,'title'=>$result['title'],'at'=>$ts,'wrong'=>$wrong];
       academy_delete_node_raw($pdo,$mistakePath);
       academy_insert_value_raw($pdo,$mistakePath,$mistakes,$u['id']);
       academy_delete_node_raw($pdo,'studentProfilesV3/'.$u['id'].'/lastActiveAt');academy_insert_value_raw($pdo,'studentProfilesV3/'.$u['id'].'/lastActiveAt',$ts,$u['id']);
       $pdo->commit();
     }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
     academy_audit($u['id'],'student.quiz.submit',$lessonId,['quizId'=>$quizId,'score'=>$scored['score'],'count'=>$scored['questions']]);
     academy_json(['ok'=>true,'result'=>$result,'review'=>$assessmentReview,'xpEarned'=>$xpEarned,'reused'=>false]);
   }finally{$pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($lock).')');}
 }
 if($route==='/student/assignments/submit'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $b=academy_body();$id=trim((string)($b['assignmentId']??''));if(!preg_match('/^[a-zA-Z0-9_-]{6,100}$/D',$id))academy_json(['ok'=>false,'error'=>'assignment_invalid'],422);
   $a=academy_read_node('assignments/'.$id);$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($a)||!is_array($profile)||($a['isHidden']??false)===true||($a['status']??'published')!=='published')academy_json(['ok'=>false,'error'=>'assignment_not_found'],404);
   $allowed=academy_scope_matches($a,$profile);
   if(($a['targetMode']??'stage')==='group'){$gid=(string)($a['targetGroupId']??'');$ids=$profile['groupIds']??[];$allowed=$allowed&&$gid!==''&&is_array($ids)&&(array_is_list($ids)?in_array($gid,array_map('strval',$ids),true):!empty($ids[$gid]));}
   if(!$allowed)academy_json(['ok'=>false,'error'=>'assignment_scope_mismatch'],403);
   $answer=trim((string)($b['answer']??''));$link=trim((string)($b['link']??''));if(($answer===''&&$link==='')||mb_strlen($answer)>12000||mb_strlen($link)>700)academy_json(['ok'=>false,'error'=>'answer_invalid'],422);if($link!==''&&(!filter_var($link,FILTER_VALIDATE_URL)||!in_array(strtolower((string)parse_url($link,PHP_URL_SCHEME)),['http','https'],true)))academy_json(['ok'=>false,'error'=>'invalid_link'],422);
   $path='assignmentSubmissions/'.$id.'/'.$u['id'];$lock='academy:assignment:'.hash('sha256',$id.'|'.$u['id']);$got=(int)$pdo->query('SELECT GET_LOCK('.$pdo->quote($lock).',5)')->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);
   try{$existing=academy_read_node($path);if(is_array($existing)&&($existing['status']??'')==='graded')academy_json(['ok'=>false,'error'=>'assignment_already_graded'],409);
     $now=academy_now_ms();$submittedAt=is_array($existing)?(int)($existing['submittedAt']??$now):$now;$payload=['answer'=>$answer,'link'=>$link,'status'=>'submitted','submittedAt'=>$submittedAt,'updatedAt'=>$now,'late'=>!empty($a['dueAt'])&&$submittedAt>(int)$a['dueAt'],'studentName'=>$profile['name']??$u['display_name'],'assignmentTitle'=>$a['title']??'واجب','subject'=>$a['subject']??''];academy_write_node($path,$payload,$u['id']);}
   finally{$pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($lock).')');}
   academy_audit($u['id'],'assignment.submit',$id);academy_json(['ok'=>true,'submission'=>$payload]);
 }
 if($route==='/teacher/at-risk'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$assignments=academy_teacher_assignments($u['id']);$students=academy_read_node('studentProfilesV3');$rows=[];$total=0;$now=academy_now_ms();
   if(is_array($students))foreach($students as$sid=>$p){if(!is_array($p))continue;$matches=[];foreach($assignments as$a)if(academy_scope_matches($a,$p))$matches[]=$a;if(!$matches)continue;$total++;$subjects=array_values(array_unique(array_filter(array_map(fn($a)=>(string)($a['subject']??''),$matches))));$history=academy_list_values($p['quizHistory']??[]);$scores=[];foreach($history as$h)if(is_array($h)&&(!$subjects||in_array((string)($h['subject']??''),$subjects,true))&&($h['createdAt']??0)>=$now-30*86400000)$scores[]=(float)($h['percentage']??$h['score']??0);$avg=$scores?array_sum($scores)/count($scores):null;$last=(int)($p['lastActiveAt']??($p['activity']['lastSeenAt']??0));$days=$last?max(0,(int)floor(($now-$last)/86400000)):999;$progress=[];foreach($subjects as$sub){$v=$p['subjectProgressV3'][$p['educationType']??'public'][$p['stage']??''][$p['grade']??''][$sub]??($p['subjectProgress'][$sub]??null);if($v!==null)$progress[]=(float)$v;}$prog=$progress?array_sum($progress)/count($progress):null;$reasons=[];if($days>=7)$reasons[]=$days>=999?'لم يسجل نشاطًا بعد':'غائب منذ '.$days.' أيام';if($avg!==null&&count($scores)>=2&&$avg<60)$reasons[]='متوسط الاختبارات أقل من 60%';if($prog!==null&&$prog<30)$reasons[]='تقدم المادة أقل من 30%';if(!$reasons)continue;$a=$matches[0];$rows[]=['id'=>(string)$sid,'name'=>$p['name']??'طالب','grade'=>$p['grade']??'','stage'=>$p['stage']??'','subject'=>$a['subject']??'','subjectName'=>$a['subjectName']??($a['subject']??''),'averageScore'=>$avg===null?null:round($avg,1),'progress'=>$prog===null?null:round($prog,1),'daysInactive'=>$days,'reasons'=>$reasons];}
   usort($rows,function($a,$b){$wa=count($a['reasons']??[])*100+($a['daysInactive']??0);$wb=count($b['reasons']??[])*100+($b['daysInactive']??0);return$wb<=>$wa;});academy_json(['ok'=>true,'totalScopedStudents'=>$total,'students'=>array_slice($rows,0,80)]);
 }
 /* V31/2: assignment lifecycle, teacher-scoped analytics, no direct grade writes from browsers. */
 if($route==='/admin/assignments/pending'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $all=academy_read_node('assignments');$items=[];if(is_array($all))foreach($all as$id=>$a)if(is_array($a)&&($a['status']??'published')==='pending')$items[]=array_merge($a,['id'=>(string)$id]);
   usort($items,fn($a,$b)=>(int)($b['createdAt']??0)<=>(int)($a['createdAt']??0));academy_json(['ok'=>true,'items'=>array_slice($items,0,200)]);
 }
 if($route==='/admin/assignments/decision'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $b=academy_body();$id=trim((string)($b['id']??''));$decision=(string)($b['decision']??'');if(!preg_match('/^[a-zA-Z0-9_-]{6,100}$/D',$id)||!in_array($decision,['approve','reject'],true))academy_json(['ok'=>false,'error'=>'decision_invalid'],422);
   $path='assignments/'.$id;$lock='academy:assignment-review:'.hash('sha256',$id);$got=(int)$pdo->query('SELECT GET_LOCK('.$pdo->quote($lock).',5)')->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);
   try{$item=academy_read_node($path);if(!is_array($item)||($item['status']??'')!=='pending')academy_json(['ok'=>false,'error'=>'assignment_not_pending'],409);$item['status']=$decision==='approve'?'published':'rejected';$item['reviewedBy']=$u['id'];$item['reviewedAt']=academy_now_ms();$item['updatedAt']=$item['reviewedAt'];academy_write_node($path,$item,$u['id']);}
   finally{$pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($lock).')');}
   academy_audit($u['id'],'admin.assignment.decision',$id,['decision'=>$decision]);academy_json(['ok'=>true,'status'=>$item['status']]);
 }
 if($route==='/teacher/assignments/create'&&$method==='POST'){
   $u=academy_current_user(true);
   if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   academy_rate_limit('teacher-assignment-'.$u['id'],40,3600);
   $b=academy_body();$title=trim((string)($b['title']??''));$instructions=trim((string)($b['instructions']??''));
   if(mb_strlen($title)<3||mb_strlen($title)>140||mb_strlen($instructions)>5000)academy_json(['ok'=>false,'error'=>'assignment_invalid'],422);
   $scope=['type'=>(string)($b['type']??''),'stage'=>(string)($b['stage']??''),'grade'=>(string)($b['grade']??''),'subject'=>(string)($b['subject']??'')];
   if(!in_array($scope['type'],['public','azhar'],true)||!in_array($scope['stage'],['primary','prep','sec'],true)||!preg_match('/^[1-6]$/D',$scope['grade'])||!preg_match('/^[a-zA-Z0-9_-]{1,90}$/D',$scope['subject'])||!academy_teacher_scope_allowed($u['id'],$scope))academy_json(['ok'=>false,'error'=>'scope_not_assigned'],403);
   $dueAt=(int)($b['dueAt']??0);$ts=academy_now_ms();if($dueAt<$ts-3600000||$dueAt>$ts+366*86400000)academy_json(['ok'=>false,'error'=>'due_date_invalid'],422);
   $targetMode=(string)($b['targetMode']??'stage');$groupId=trim((string)($b['targetGroupId']??''));
   if(!in_array($targetMode,['stage','group'],true))academy_json(['ok'=>false,'error'=>'invalid_target'],422);
   if($targetMode==='group'){$g=academy_read_node('teacherGroupsV4/'.$u['id'].'/'.$groupId);if(!is_array($g)||($g['active']??false)!==true||!academy_scope_matches($scope,['educationType'=>$g['type']??'','stage'=>$g['stage']??'','grade'=>$g['grade']??'']))academy_json(['ok'=>false,'error'=>'group_not_owned'],403);foreach(['subject','type','stage','grade']as$k)if((string)($g[$k]??'')!==$scope[$k])academy_json(['ok'=>false,'error'=>'group_scope_mismatch'],422);}else $groupId='';
   $id=substr(str_replace('-','',academy_uuid()),0,24);$row=['id'=>$id,'teacherId'=>$u['id'],'title'=>$title,'description'=>$instructions,'instructions'=>$instructions,'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>$scope['grade'],'subject'=>$scope['subject'],'subjectName'=>trim((string)($b['subjectName']??$scope['subject'])),'targetMode'=>$targetMode,'targetGroupId'=>$groupId,'dueAt'=>$dueAt,'maxScore'=>100,'status'=>'pending','isHidden'=>false,'createdAt'=>$ts,'updatedAt'=>$ts];
   academy_write_node('assignments/'.$id,$row,$u['id']);academy_audit($u['id'],'teacher.assignment.create',$id);academy_json(['ok'=>true,'assignment'=>$row],201);
 }
 if($route==='/teacher/assignments/list'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $all=academy_read_node('assignments');$out=[];if(is_array($all))foreach($all as$id=>$row){if(!is_array($row)||($row['teacherId']??'')!==$u['id'])continue;$row['id']=(string)$id;$out[]=$row;}
   usort($out,fn($a,$b)=>(int)($b['createdAt']??0)<=>(int)($a['createdAt']??0));academy_json(['ok'=>true,'items'=>array_slice($out,0,200)]);
 }
 if($route==='/teacher/assignments/submissions'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $id=trim((string)($_GET['id']??''));if(!preg_match('/^[a-zA-Z0-9_-]{6,100}$/D',$id)||!academy_teacher_owns_assignment($u['id'],$id))academy_json(['ok'=>false,'error'=>'assignment_not_owned'],403);
   $values=academy_read_node('assignmentSubmissions/'.$id);$items=[];if(is_array($values))foreach($values as$sid=>$r){if(!is_array($r))continue;$items[]=['studentId'=>(string)$sid,'studentName'=>(string)($r['studentName']??'طالب'),'answer'=>$r['answer']??'','link'=>$r['link']??'','status'=>$r['status']??'submitted','late'=>!empty($r['late']),'submittedAt'=>(int)($r['submittedAt']??0),'score'=>isset($r['score'])?(int)$r['score']:null,'feedback'=>$r['feedback']??''];}
   usort($items,fn($a,$b)=>$b['submittedAt']<=>$a['submittedAt']);academy_json(['ok'=>true,'items'=>array_slice($items,0,250)]);
 }
 if($route==='/teacher/assignments/grade'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $b=academy_body();$id=trim((string)($b['assignmentId']??''));$sid=trim((string)($b['studentId']??''));$score=filter_var($b['score']??null,FILTER_VALIDATE_INT);$feedback=trim((string)($b['feedback']??''));
   if(!preg_match('/^[a-zA-Z0-9_-]{6,100}$/D',$id)||!preg_match('/^[a-f0-9-]{36}$/D',$sid)||$score===false||$score<0||$score>100||mb_strlen($feedback)>1500)academy_json(['ok'=>false,'error'=>'grade_invalid'],422);
   if(!academy_teacher_owns_assignment($u['id'],$id))academy_json(['ok'=>false,'error'=>'assignment_not_owned'],403);
   $path='assignmentSubmissions/'.$id.'/'.$sid;$lock='academy:assignment:'.hash('sha256',$id.'|'.$sid);$got=(int)$pdo->query('SELECT GET_LOCK('.$pdo->quote($lock).',5)')->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);
   try{$existing=academy_read_node($path);if(!is_array($existing)||!in_array(($existing['status']??''),['submitted','graded'],true))academy_json(['ok'=>false,'error'=>'submission_not_found'],404);$existing['score']=$score;$existing['feedback']=$feedback;$existing['status']='graded';$existing['gradedAt']=academy_now_ms();$existing['gradedBy']=$u['id'];$existing['updatedAt']=$existing['gradedAt'];academy_write_node($path,$existing,$u['id']);}
   finally{$pdo->query('SELECT RELEASE_LOCK('.$pdo->quote($lock).')');}
   academy_audit($u['id'],'teacher.assignment.grade',$id,['studentId'=>$sid]);academy_json(['ok'=>true,'submission'=>['status'=>'graded','score'=>$score,'feedback'=>$feedback]]);
 }
 if($route==='/student/assignments'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'profile_missing'],404);
   $all=academy_read_node('assignments');$items=[];$mine=[];
   if(is_array($all))foreach($all as$id=>$a){if(!is_array($a)||($a['isHidden']??false)===true||($a['status']??'published')!=='published'||!academy_scope_matches($a,$profile))continue;
      if(($a['targetMode']??'stage')==='group'){$gid=(string)($a['targetGroupId']??'');$ids=$profile['groupIds']??[];if($gid===''||!is_array($ids)||(array_is_list($ids)?!in_array($gid,array_map('strval',$ids),true):empty($ids[$gid])))continue;}
      $items[]=array_merge($a,['id'=>(string)$id]);$sub=academy_read_node('assignmentSubmissions/'.$id.'/'.$u['id']);if(is_array($sub))$mine[(string)$id]=['status'=>$sub['status']??'submitted','score'=>$sub['score']??null,'feedback'=>$sub['feedback']??'','submittedAt'=>$sub['submittedAt']??0];
   }usort($items,fn($a,$b)=>(int)($a['dueAt']??0)<=>(int)($b['dueAt']??0));academy_json(['ok'=>true,'items'=>array_slice($items,0,150),'submissions'=>$mine]);
 }
 /* V31/3: scoped progress for teachers; private reports for verified parents. */
 if($route==='/teacher/students/progress'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $scopes=academy_teacher_assignments($u['id']);$students=academy_read_node('studentProfilesV3');$all=academy_read_node('assignments');$submissionRoot=academy_read_node('assignmentSubmissions');
   $mine=[];if(is_array($all))foreach($all as$aid=>$a)if(is_array($a)&&($a['teacherId']??'')===$u['id']&&($a['status']??'')==='published'&&empty($a['isHidden']))$mine[(string)$aid]=$a;
   $items=[];$total=0;$gradedAll=0;$submittedAll=0;$pendingAll=0;
   if(is_array($students))foreach($students as$sid=>$p){
     if(!is_array($p))continue;$matched=[];foreach($scopes as$scope)if(academy_scope_matches($scope,$p))$matched[]=$scope;
     if(!$matched)continue;$total++;
     $allowedSubjects=array_values(array_unique(array_filter(array_map(fn($scope)=>(string)($scope['subject']??''),$matched))));
     $scores=[];foreach(academy_list_values($p['quizHistory']??[])as$h){if(!is_array($h)||!isset($h['subject'],$h['correct'],$h['questions']))continue;
       if($allowedSubjects&&!in_array((string)$h['subject'],$allowedSubjects,true))continue;
       if(!empty($h['type'])&&$h['type']!==($p['educationType']??$p['type']??''))continue;
       if(!empty($h['stage'])&&$h['stage']!==($p['stage']??''))continue;
       if(!empty($h['grade'])&&(string)$h['grade']!==(string)($p['grade']??''))continue;
       $num=(int)$h['questions'];if($num>0)$scores[]=max(0,min(100,100*(int)$h['correct']/$num));
     }
     $homeworkTotal=0;$graded=0;$submitted=0;$missing=0;$homeworkScores=[];$now=academy_now_ms();
     foreach($mine as$aid=>$a){if(!academy_scope_matches($a,$p))continue;
       if(($a['targetMode']??'stage')==='group'){$gid=(string)($a['targetGroupId']??'');$ids=$p['groupIds']??[];
         if(!$gid||!is_array($ids)||(array_is_list($ids)?!in_array($gid,array_map('strval',$ids),true):empty($ids[$gid])))continue;}
       $homeworkTotal++;$sub=$submissionRoot[$aid][$sid]??null;
       if(is_array($sub)&&($sub['status']??'')==='graded'&&isset($sub['score'])){$graded++;$homeworkScores[]=max(0,min(100,(int)$sub['score']));}
       elseif(is_array($sub)&&($sub['status']??'')==='submitted')$submitted++;
       elseif((int)($a['dueAt']??0)>0&&(int)$a['dueAt']<$now)$missing++;
     }
     $gradedAll+=$graded;$submittedAll+=$submitted;$pendingAll+=$missing;
     $items[]=['studentId'=>(string)$sid,'name'=>mb_substr((string)($p['name']??'طالب'),0,100),'stage'=>(string)($p['stage']??''),'grade'=>(string)($p['grade']??''),
       'quizAttempts'=>count($scores),'quizAverage'=>$scores?round(array_sum($scores)/count($scores),1):null,
       'homeworkTotal'=>$homeworkTotal,'homeworkGraded'=>$graded,'homeworkSubmitted'=>$submitted,'homeworkOverdue'=>$missing,
       'homeworkAverage'=>$homeworkScores?round(array_sum($homeworkScores)/count($homeworkScores),1):null];
   }
   usort($items,fn($a,$b)=>($b['homeworkOverdue']<=>$a['homeworkOverdue'])?:strcmp($a['name'],$b['name']));
   academy_json(['ok'=>true,'totalScopedStudents'=>$total,'homeworkGraded'=>$gradedAll,'homeworkSubmitted'=>$submittedAll,'homeworkOverdue'=>$pendingAll,'items'=>array_slice($items,0,150)]);
 }
 if($route==='/parent/children/learning-report'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='parent')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $sid=trim((string)($_GET['studentId']??''));if(!preg_match('/^[a-f0-9-]{36}$/D',$sid))academy_json(['ok'=>false,'error'=>'student_invalid'],422);
   $link=academy_read_node('parentLinksV4/'.$u['id'].'/'.$sid);
   if(!is_array($link)||($link['studentId']??'')!==$sid)academy_json(['ok'=>false,'error'=>'student_not_linked'],403);
   $p=academy_read_node('studentProfilesV3/'.$sid);if(!is_array($p))academy_json(['ok'=>false,'error'=>'student_not_found'],404);
   $all=academy_read_node('assignments');$items=[];$graded=0;$submitted=0;$overdue=0;$sum=0;$now=academy_now_ms();
   if(is_array($all))foreach($all as$aid=>$a){
     if(!is_array($a)||($a['status']??'')!=='published'||!empty($a['isHidden'])||!academy_scope_matches($a,$p))continue;
     if(($a['targetMode']??'stage')==='group'){$gid=(string)($a['targetGroupId']??'');$ids=$p['groupIds']??[];
       if(!$gid||!is_array($ids)||(array_is_list($ids)?!in_array($gid,array_map('strval',$ids),true):empty($ids[$gid])))continue;}
     $r=academy_read_node('assignmentSubmissions/'.$aid.'/'.$sid);$status='new';$score=null;$feedback='';
     if(is_array($r)&&($r['status']??'')==='graded'&&isset($r['score'])){$status='graded';$score=max(0,min(100,(int)$r['score']));$feedback=mb_substr((string)($r['feedback']??''),0,1500);$graded++;$sum+=$score;}
     elseif(is_array($r)&&($r['status']??'')==='submitted'){$status='submitted';$submitted++;}
     elseif((int)($a['dueAt']??0)>0&&(int)$a['dueAt']<$now){$status='overdue';$overdue++;}
     $items[]=['id'=>(string)$aid,'title'=>mb_substr((string)($a['title']??'واجب'),0,140),'subject'=>(string)($a['subject']??''),'dueAt'=>(int)($a['dueAt']??0),'status'=>$status,'score'=>$score,'feedback'=>$feedback];
   }
   usort($items,fn($a,$b)=>($b['dueAt']<=>$a['dueAt']));
   academy_json(['ok'=>true,'studentId'=>$sid,'homework'=>['total'=>count($items),'graded'=>$graded,'submitted'=>$submitted,'overdue'=>$overdue,'average'=>$graded?round($sum/$graded,1):null,'items'=>array_slice($items,0,150)]]);
 }
 if($route==='/teacher/analytics/summary'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $assignments=academy_teacher_assignments($u['id']);$students=academy_read_node('studentProfilesV3');$scoped=0;$attempts=0;$sum=0;$buckets=['0-49'=>0,'50-69'=>0,'70-84'=>0,'85-100'=>0];$bySubject=[];
   if(is_array($students))foreach($students as$p){if(!is_array($p))continue;$matching=[];foreach($assignments as$a)if(academy_scope_matches($a,$p))$matching[]=$a;if(!$matching)continue;$scoped++;
     foreach(academy_list_values($p['quizHistory']??[])as$h){if(!is_array($h)||!isset($h['attemptId'],$h['lessonId'],$h['subject'],$h['correct'],$h['questions']))continue;
       $subject=(string)$h['subject'];$scopeOk=false;foreach($matching as$a)if(empty($a['subject'])||$subject===(string)$a['subject']){$scopeOk=true;break;}if(!$scopeOk)continue;
       if(!empty($h['stage'])&&$h['stage']!==($p['stage']??''))continue;if(!empty($h['grade'])&&(string)$h['grade']!==(string)($p['grade']??''))continue;
       $total=(int)$h['questions'];if($total<1)continue;$score=round(max(0,min(100,100*(int)$h['correct']/$total)));$attempts++;$sum+=$score;$band=$score<50?'0-49':($score<70?'50-69':($score<85?'70-84':'85-100'));$buckets[$band]++;
       if(!isset($bySubject[$subject]))$bySubject[$subject]=['subject'=>$subject,'attempts'=>0,'totalScore'=>0];$bySubject[$subject]['attempts']++;$bySubject[$subject]['totalScore']+=$score;
     }
   }
   $subjectRows=[];foreach($bySubject as$x)$subjectRows[]=['subject'=>$x['subject'],'attempts'=>$x['attempts'],'average'=>round($x['totalScore']/max(1,$x['attempts']),1)];usort($subjectRows,fn($a,$b)=>$b['attempts']<=>$a['attempts']);academy_json(['ok'=>true,'students'=>$scoped,'attempts'=>$attempts,'average'=>$attempts?round($sum/$attempts,1):null,'buckets'=>$buckets,'subjects'=>array_slice($subjectRows,0,30)]);
 }
 if($route==='/teacher/assignments/delete'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$id=trim((string)($b['id']??''));if(!academy_teacher_owns_assignment($u['id'],$id))academy_json(['ok'=>false,'error'=>'assignment_not_owned'],403);$pdo->beginTransaction();try{academy_delete_node_raw($pdo,'assignmentSubmissions/'.$id);academy_delete_node_raw($pdo,'assignments/'.$id);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}academy_audit($u['id'],'teacher.assignment.delete',$id);academy_json(['ok'=>true]);
 }
 if($route==='/learning/diagnostic/start'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$subject=trim((string)($b['subject']??''));$count=max(5,min(30,(int)($b['count']??12)));$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($profile)||$subject==='')academy_json(['ok'=>false,'error'=>'invalid_diagnostic'],422);$bank=academy_read_node('questionBankV4');$pool=[];
   if(is_array($bank))foreach($bank as$id=>$q){if(!is_array($q)||($q['status']??'')!=='approved'||(string)($q['subject']??'')!==$subject)continue;if(!empty($q['type'])&&$q['type']!==($profile['educationType']??''))continue;if(!empty($q['stage'])&&$q['stage']!==($profile['stage']??''))continue;if(!empty($q['grade'])&&(string)$q['grade']!==(string)($profile['grade']??''))continue;$q['id']=(string)$id;$pool[]=$q;}
   if(count($pool)<3)academy_json(['ok'=>false,'error'=>'not_enough_questions'],422);shuffle($pool);$selected=[];foreach([1,2,3]as$d){$chunk=array_values(array_filter($pool,fn($q)=>(int)($q['difficulty']??2)===$d));shuffle($chunk);$want=(int)ceil($count/3);$selected=array_merge($selected,array_slice($chunk,0,$want));}$seen=[];$selected=array_values(array_filter($selected,function($q)use(&$seen){$id=$q['id'];if(isset($seen[$id]))return false;$seen[$id]=true;return true;}));if(count($selected)<$count)foreach($pool as$q){if(!isset($seen[$q['id']])){$selected[]=$q;$seen[$q['id']]=true;if(count($selected)>=$count)break;}}$selected=array_slice($selected,0,$count);$attemptId=substr(str_replace('-','',academy_uuid()),0,24);$ts=academy_now_ms();$stored=['id'=>$attemptId,'subject'=>$subject,'questions'=>$selected,'createdAt'=>$ts,'expiresAt'=>$ts+2*3600000,'used'=>false];academy_write_node('learningV4/diagnosticAttempts/'.$u['id'].'/'.$attemptId,$stored,$u['id']);$public=[];foreach($selected as$q)$public[]=['id'=>$q['id'],'question'=>$q['question']??$q['text']??'','options'=>$q['options']??$q['opts']??[],'difficulty'=>(int)($q['difficulty']??2),'skill'=>$q['skill']??'','lessonId'=>$q['lessonId']??''];academy_json(['ok'=>true,'attemptId'=>$attemptId,'questions'=>$public,'expiresAt'=>$stored['expiresAt']]);
 }
 if($route==='/learning/diagnostic/submit'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$attemptId=trim((string)($b['attemptId']??''));$attempt=academy_read_node('learningV4/diagnosticAttempts/'.$u['id'].'/'.$attemptId);if(!is_array($attempt)||($attempt['used']??false)||($attempt['expiresAt']??0)<academy_now_ms())academy_json(['ok'=>false,'error'=>'invalid_attempt'],422);$answers=$b['answers']??[];if(!is_array($answers))$answers=[];$questions=academy_list_values($attempt['questions']??[]);$correct=0;$skills=[];$details=[];foreach($questions as$i=>$q){if(!is_array($q))continue;$ans=isset($answers[$i])?(int)$answers[$i]:-1;$ok=$ans===(int)($q['correctAnswer']??-999);if($ok)$correct++;$skill=(string)($q['skill']??($q['lessonId']??'عام'));if(!isset($skills[$skill]))$skills[$skill]=['skill'=>$skill,'lessonId'=>$q['lessonId']??'','correct'=>0,'total'=>0];$skills[$skill]['total']++;if($ok)$skills[$skill]['correct']++;$details[]=['id'=>$q['id']??'','correct'=>$ok,'correctAnswer'=>(int)($q['correctAnswer']??0),'explanation'=>$q['explanation']??''];}$total=max(1,count($questions));$score=(int)round($correct/$total*100);$skillRows=[];foreach($skills as$x){$x['score']=(int)round($x['correct']/max(1,$x['total'])*100);$skillRows[]=$x;}$weak=array_values(array_filter($skillRows,fn($x)=>$x['score']<60));$ts=academy_now_ms();$report=['attemptId'=>$attemptId,'subject'=>$attempt['subject']??'','score'=>$score,'correct'=>$correct,'total'=>count($questions),'skills'=>$skillRows,'weaknesses'=>$weak,'recommendations'=>array_values(array_unique(array_filter(array_map(fn($x)=>$x['lessonId']??'',$weak)))),'createdAt'=>$ts];academy_write_node('learningV4/diagnostics/'.$u['id'].'/'.($attempt['subject']??'general').'/'.$attemptId,$report,$u['id']);$attempt['used']=true;$attempt['submittedAt']=$ts;unset($attempt['questions']);academy_write_node('learningV4/diagnosticAttempts/'.$u['id'].'/'.$attemptId,$attempt,$u['id']);academy_audit($u['id'],'learning.diagnostic.complete',$attemptId,['score'=>$score,'subject'=>$attempt['subject']??'']);academy_json(['ok'=>true,'report'=>$report,'details'=>$details]);
 }
 if($route==='/events/content'&&$method==='POST'){
   $u=academy_current_user(true);if(!in_array($u['primary_role'],['student','teacher','admin'],true))academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$id=trim((string)($b['contentId']??''));$event=(string)($b['event']??'');if($id===''||!in_array($event,['views','completions','quiz'],true))academy_json(['ok'=>false,'error'=>'invalid_event'],422);$path='contentAnalytics/'.$id;$lock='academy:'.hash('sha256',$path);$got=(int)$pdo->query("SELECT GET_LOCK(".$pdo->quote($lock).",5)")->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);try{$a=academy_read_node($path);if(!is_array($a))$a=[];if($event==='views')$a['views']=(int)($a['views']??0)+1;if($event==='completions')$a['completions']=(int)($a['completions']??0)+1;if($event==='quiz'){$score=max(0,min(100,(float)($b['score']??0)));$a['quizAttempts']=(int)($a['quizAttempts']??0)+1;$a['quizScoreTotal']=(float)($a['quizScoreTotal']??0)+$score;$a['quizAverage']=(int)round($a['quizScoreTotal']/max(1,$a['quizAttempts']));$stats=$a['questionStats']??[];foreach(($b['questionResults']??[])as$r){if(!is_array($r))continue;$idx=(string)($r['index']??'');if($idx==='')continue;$rec=$stats[$idx]??[];$rec['attempts']=(int)($rec['attempts']??0)+1;$rec['correct']=(int)($rec['correct']??0)+(!empty($r['correct'])?1:0);$stats[$idx]=$rec;}$a['questionStats']=$stats;}$a['updatedAt']=academy_now_ms();academy_write_node($path,$a,$u['id']);}finally{$pdo->query("SELECT RELEASE_LOCK(".$pdo->quote($lock).")");}academy_json(['ok'=>true]);
 }
 if($route==='/events/question-answer'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);academy_rate_limit('question-answer-'.$u['id'],360,3600);$b=academy_body();$questionId=trim((string)($b['questionId']??''));if($questionId===''||mb_strlen($questionId)>190)academy_json(['ok'=>false,'error'=>'question_id_invalid'],422);$correct=!empty($b['correct']);$answer=$b['answer']??'';if(is_array($answer)||is_object($answer))$answer='';$answer=mb_substr((string)$answer,0,120);$path='analyticsV4/questions/'.$questionId;$lock='academy:question:'.hash('sha256',$questionId);$got=(int)$pdo->query("SELECT GET_LOCK(".$pdo->quote($lock).",5)")->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);try{$stats=academy_read_node($path);if(!is_array($stats))$stats=['attempts'=>0,'correct'=>0,'wrong'=>0,'answers'=>[]];$stats['attempts']=(int)($stats['attempts']??0)+1;$correct?$stats['correct']=(int)($stats['correct']??0)+1:$stats['wrong']=(int)($stats['wrong']??0)+1;$key=preg_replace('/[.$#[\]\/]/','_',$answer);$key=mb_substr($key!==''?$key:'_blank',0,80);$answers=is_array($stats['answers']??null)?$stats['answers']:[];$answers[$key]=(int)($answers[$key]??0)+1;$stats['answers']=$answers;$stats['difficultyIndex']=$stats['attempts']?(int)round(((int)$stats['wrong']/$stats['attempts'])*100):0;$stats['updatedAt']=academy_now_ms();academy_write_node($path,$stats,$u['id']);}finally{$pdo->query("SELECT RELEASE_LOCK(".$pdo->quote($lock).")");}academy_json(['ok'=>true]);
 }
 if($route==='/teacher/live-competitions'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$raw=academy_read_node('liveCompetitionsV1');$rows=[];if(is_array($raw))foreach($raw as$id=>$room){if(!is_array($room)||($room['teacherId']??'')!==$u['id'])continue;$participants=academy_read_node('liveCompetitionParticipantsV1/'.$id);$room['id']=(string)$id;$room['participantCount']=is_array($participants)?count($participants):0;$rows[]=$room;}usort($rows,fn($a,$b)=>(int)($b['createdAt']??0)<=>(int)($a['createdAt']??0));academy_json(['ok'=>true,'rooms'=>array_slice($rows,0,30)]);
 }
 if($route==='/teacher/live-competitions/create'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$title=trim((string)($b['title']??''));if(mb_strlen($title)<2||mb_strlen($title)>90)academy_json(['ok'=>false,'error'=>'title_invalid'],422);$count=max(3,min(30,(int)($b['questionCount']??10)));$scope=['type'=>(string)($b['type']??'public'),'stage'=>(string)($b['stage']??''),'grade'=>(string)($b['grade']??''),'subject'=>(string)($b['subject']??'')];$matched=null;foreach(academy_teacher_assignments($u['id'])as$a){$ok=true;foreach(['type','stage','grade','subject']as$k)if(!empty($a[$k])&&(string)$a[$k]!==$scope[$k])$ok=false;if($ok){$matched=$a;break;}}if(!$matched)academy_json(['ok'=>false,'error'=>'scope_not_assigned'],403);
   $bank=academy_read_node('questionBankV4');$pool=[];if(is_array($bank))foreach($bank as$id=>$q){if(!is_array($q)||($q['status']??'approved')!=='approved')continue;if(($q['type']??'public')!==$scope['type']||($q['stage']??'')!==$scope['stage']||(string)($q['grade']??'')!==$scope['grade']||($q['subject']??'')!==$scope['subject'])continue;$opts=academy_list_values($q['options']??($q['opts']??[]));if(count($opts)<2||trim((string)($q['question']??$q['text']??''))==='')continue;$pool[]=['id'=>(string)$id,'question'=>(string)($q['question']??$q['text']),'options'=>$opts,'correctAnswer'=>max(0,min(count($opts)-1,(int)($q['correctAnswer']??0))),'explanation'=>(string)($q['explanation']??''),'skill'=>(string)($q['skill']??''),'difficulty'=>(int)($q['difficulty']??2)];}if(count($pool)<3)academy_json(['ok'=>false,'error'=>'not_enough_questions','available'=>count($pool)],422);shuffle($pool);$questions=array_slice($pool,0,min($count,count($pool)));$id=substr(str_replace('-','',academy_uuid()),0,20);do{$code='QUIZ-'.strtoupper(substr(bin2hex(random_bytes(4)),0,6));}while(academy_read_node('liveCompetitionCodesV1/'.$code)!==null);$ts=academy_now_ms();$room=['id'=>$id,'code'=>$code,'title'=>$title,'teacherId'=>$u['id'],'teacherName'=>$matched['teacherName']??($u['display_name']??'المدرس'),'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>$scope['grade'],'subject'=>$scope['subject'],'subjectName'=>$matched['subjectName']??$scope['subject'],'status'=>'waiting','questionCount'=>count($questions),'currentIndex'=>-1,'createdAt'=>$ts,'updatedAt'=>$ts];$pdo->beginTransaction();try{academy_delete_node_raw($pdo,'liveCompetitionsV1/'.$id);academy_insert_value_raw($pdo,'liveCompetitionsV1/'.$id,$room,$u['id']);academy_delete_node_raw($pdo,'liveCompetitionSecretsV1/'.$id);academy_insert_value_raw($pdo,'liveCompetitionSecretsV1/'.$id,['questions'=>$questions],$u['id']);academy_delete_node_raw($pdo,'liveCompetitionCodesV1/'.$code);academy_insert_value_raw($pdo,'liveCompetitionCodesV1/'.$code,['roomId'=>$id,'teacherId'=>$u['id'],'active'=>true,'createdAt'=>$ts],$u['id']);$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}academy_audit($u['id'],'live_competition.create',$id,['code'=>$code,'questions'=>count($questions)]);academy_json(['ok'=>true,'room'=>$room],201);
 }
 if($route==='/teacher/live-competitions/state'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$id=trim((string)($_GET['id']??''));$room=academy_read_node('liveCompetitionsV1/'.$id);if(!is_array($room)||($room['teacherId']??'')!==$u['id'])academy_json(['ok'=>false,'error'=>'room_not_found'],404);$secret=academy_read_node('liveCompetitionSecretsV1/'.$id);$questions=academy_list_values(is_array($secret)?($secret['questions']??[]):[]);$idx=(int)($room['currentIndex']??-1);$question=isset($questions[$idx])?$questions[$idx]:null;$parts=academy_read_node('liveCompetitionParticipantsV1/'.$id);$board=[];if(is_array($parts))foreach($parts as$sid=>$p)if(is_array($p))$board[]=['studentId'=>(string)$sid,'name'=>$p['name']??'طالب','score'=>(int)($p['score']??0),'correct'=>(int)($p['correct']??0),'answersCount'=>(int)($p['answersCount']??0),'joinedAt'=>$p['joinedAt']??0];usort($board,fn($a,$b)=>($b['score']<=>$a['score'])?:($a['joinedAt']<=>$b['joinedAt']));academy_json(['ok'=>true,'room'=>$room,'question'=>$question,'leaderboard'=>$board]);
 }
 if($route==='/teacher/live-competitions/action'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$id=trim((string)($b['id']??''));$action=(string)($b['action']??'');$room=academy_read_node('liveCompetitionsV1/'.$id);if(!is_array($room)||($room['teacherId']??'')!==$u['id'])academy_json(['ok'=>false,'error'=>'room_not_found'],404);$ts=academy_now_ms();$count=(int)($room['questionCount']??0);if($action==='start'){if(($room['status']??'')==='ended')academy_json(['ok'=>false,'error'=>'room_ended'],409);$room['status']='live';$room['currentIndex']=max(0,(int)($room['currentIndex']??-1));$room['startedAt']=$room['startedAt']??$ts;$room['questionStartedAt']=$ts;}elseif($action==='next'){if(($room['status']??'')!=='live')academy_json(['ok'=>false,'error'=>'room_not_live'],409);$next=(int)($room['currentIndex']??-1)+1;if($next>=$count){$room['status']='ended';$room['endedAt']=$ts;}else{$room['currentIndex']=$next;$room['questionStartedAt']=$ts;}}elseif($action==='end'){$room['status']='ended';$room['endedAt']=$ts;}else academy_json(['ok'=>false,'error'=>'invalid_action'],422);$room['updatedAt']=$ts;academy_write_node('liveCompetitionsV1/'.$id,$room,$u['id']);if(($room['status']??'')==='ended'&&!empty($room['code'])){$idx=academy_read_node('liveCompetitionCodesV1/'.$room['code']);if(is_array($idx)){ $idx['active']=false;$idx['updatedAt']=$ts;academy_write_node('liveCompetitionCodesV1/'.$room['code'],$idx,$u['id']);}}academy_audit($u['id'],'live_competition.'.$action,$id);academy_json(['ok'=>true,'room'=>$room]);
 }
 if($route==='/student/live-competitions/join'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$code=strtoupper(trim((string)($b['code']??'')));$idx=academy_read_node('liveCompetitionCodesV1/'.$code);if(!is_array($idx)||($idx['active']??false)!==true)academy_json(['ok'=>false,'error'=>'invalid_room_code'],404);$id=(string)($idx['roomId']??'');$room=academy_read_node('liveCompetitionsV1/'.$id);$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($room)||($room['status']??'')==='ended'||!is_array($profile))academy_json(['ok'=>false,'error'=>'room_unavailable'],409);if(!academy_scope_matches($room,$profile))academy_json(['ok'=>false,'error'=>'room_scope_mismatch'],422);$path='liveCompetitionParticipantsV1/'.$id.'/'.$u['id'];$existing=academy_read_node($path);$participant=is_array($existing)?$existing:['studentId'=>$u['id'],'name'=>$profile['name']??$u['display_name'],'score'=>0,'correct'=>0,'answersCount'=>0,'answers'=>[],'joinedAt'=>academy_now_ms()];$participant['lastSeenAt']=academy_now_ms();academy_write_node($path,$participant,$u['id']);academy_audit($u['id'],'live_competition.join',$id);academy_json(['ok'=>true,'roomId'=>$id,'room'=>['id'=>$id,'code'=>$room['code']??$code,'title'=>$room['title']??'مسابقة','teacherName'=>$room['teacherName']??'المدرس','status'=>$room['status']??'waiting']]);
 }
 if($route==='/student/live-competitions/state'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$id=trim((string)($_GET['id']??''));$room=academy_read_node('liveCompetitionsV1/'.$id);$participant=academy_read_node('liveCompetitionParticipantsV1/'.$id.'/'.$u['id']);if(!is_array($room)||!is_array($participant))academy_json(['ok'=>false,'error'=>'room_not_joined'],404);$secret=academy_read_node('liveCompetitionSecretsV1/'.$id);$questions=academy_list_values(is_array($secret)?($secret['questions']??[]):[]);$idx=(int)($room['currentIndex']??-1);$q=isset($questions[$idx])?$questions[$idx]:null;$publicQuestion=null;if(is_array($q)&&($room['status']??'')==='live')$publicQuestion=['index'=>$idx,'question'=>$q['question']??'','options'=>$q['options']??[],'skill'=>$q['skill']??'','difficulty'=>$q['difficulty']??2];$answers=is_array($participant['answers']??null)?$participant['answers']:[];$answerResult=array_key_exists($idx,$answers)&&is_array($answers[$idx])?$answers[$idx]:null;$parts=academy_read_node('liveCompetitionParticipantsV1/'.$id);$board=[];if(is_array($parts))foreach($parts as$sid=>$p)if(is_array($p))$board[]=['studentId'=>(string)$sid,'name'=>$p['name']??'طالب','score'=>(int)($p['score']??0),'correct'=>(int)($p['correct']??0),'answersCount'=>(int)($p['answersCount']??0),'joinedAt'=>$p['joinedAt']??0];usort($board,fn($a,$b)=>($b['score']<=>$a['score'])?:($a['joinedAt']<=>$b['joinedAt']));$rank=null;foreach($board as$i=>$r)if($r['studentId']===$u['id']){$rank=$i+1;break;}academy_json(['ok'=>true,'room'=>['id'=>$id,'code'=>$room['code']??'','title'=>$room['title']??'مسابقة','teacherName'=>$room['teacherName']??'المدرس','subjectName'=>$room['subjectName']??($room['subject']??''),'status'=>$room['status']??'waiting','questionCount'=>(int)($room['questionCount']??0),'currentIndex'=>$idx,'questionStartedAt'=>$room['questionStartedAt']??null],'question'=>$publicQuestion,'answerResult'=>$answerResult,'me'=>['score'=>(int)($participant['score']??0),'correct'=>(int)($participant['correct']??0),'answersCount'=>(int)($participant['answersCount']??0),'rank'=>$rank],'leaderboard'=>array_slice($board,0,20)]);
 }
 if($route==='/student/live-competitions/answer'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);academy_rate_limit('live-answer-'.$u['id'],120,600);$b=academy_body();$id=trim((string)($b['id']??''));$choice=(int)($b['choice']??-1);$askedIndex=(int)($b['index']??-1);$lock='academy:live-answer:'.hash('sha256',$id.'|'.$u['id'].'|'.$askedIndex);$got=(int)$pdo->query("SELECT GET_LOCK(".$pdo->quote($lock).",5)")->fetchColumn();if($got!==1)academy_json(['ok'=>false,'error'=>'busy'],409);try{$room=academy_read_node('liveCompetitionsV1/'.$id);$path='liveCompetitionParticipantsV1/'.$id.'/'.$u['id'];$participant=academy_read_node($path);if(!is_array($room)||!is_array($participant))academy_json(['ok'=>false,'error'=>'room_not_joined'],404);$current=(int)($room['currentIndex']??-1);if(($room['status']??'')!=='live'||$current!==$askedIndex)academy_json(['ok'=>false,'error'=>'question_changed'],409);$secret=academy_read_node('liveCompetitionSecretsV1/'.$id);$questions=academy_list_values(is_array($secret)?($secret['questions']??[]):[]);$q=$questions[$current]??null;if(!is_array($q))academy_json(['ok'=>false,'error'=>'question_missing'],404);$opts=academy_list_values($q['options']??[]);if($choice<0||$choice>=count($opts))academy_json(['ok'=>false,'error'=>'choice_invalid'],422);$answers=is_array($participant['answers']??null)?$participant['answers']:[];if(array_key_exists($current,$answers))academy_json(['ok'=>false,'error'=>'already_answered'],409);$correct=$choice===(int)($q['correctAnswer']??0);$result=['choice'=>$choice,'correct'=>$correct,'correctAnswer'=>(int)($q['correctAnswer']??0),'explanation'=>(string)($q['explanation']??''),'answeredAt'=>academy_now_ms()];$answers[$current]=$result;$participant['answers']=$answers;$participant['answersCount']=(int)($participant['answersCount']??0)+1;if($correct){$participant['correct']=(int)($participant['correct']??0)+1;$participant['score']=(int)($participant['score']??0)+100;}$participant['lastAnswerAt']=academy_now_ms();academy_write_node($path,$participant,$u['id']);academy_audit($u['id'],'live_competition.answer',$id,['index'=>$current,'correct'=>$correct]);academy_json(['ok'=>true,'result'=>$result,'score'=>(int)($participant['score']??0)]);}finally{$pdo->query("SELECT RELEASE_LOCK(".$pdo->quote($lock).")");}
 }



 if($route==='/teacher/questions/import-xlsx'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$raw=(string)($b['fileBase64']??'');if($raw==='')academy_json(['ok'=>false,'error'=>'file_required'],422);if(str_contains($raw,','))$raw=explode(',',$raw,2)[1];$bytes=base64_decode($raw,true);if($bytes===false||strlen($bytes)>8*1024*1024)academy_json(['ok'=>false,'error'=>'file_invalid'],422);if(!class_exists('ZipArchive'))academy_json(['ok'=>false,'error'=>'xlsx_not_supported'],501);
   $tmp=tempnam(sys_get_temp_dir(),'academy-xlsx-');file_put_contents($tmp,$bytes);$zip=new ZipArchive();if($zip->open($tmp)!==true){@unlink($tmp);academy_json(['ok'=>false,'error'=>'xlsx_invalid'],422);}try{$shared=[];$sharedXml=$zip->getFromName('xl/sharedStrings.xml');if($sharedXml!==false){$xml=@simplexml_load_string($sharedXml);if($xml)foreach($xml->si as$si){$parts=[];if(isset($si->t))$parts[]=(string)$si->t;foreach($si->r as$r)$parts[]=(string)$r->t;$shared[]=implode('',$parts);}}$sheet=$zip->getFromName('xl/worksheets/sheet1.xml');if($sheet===false)academy_json(['ok'=>false,'error'=>'xlsx_sheet_missing'],422);$xml=@simplexml_load_string($sheet);if(!$xml)academy_json(['ok'=>false,'error'=>'xlsx_invalid'],422);$rows=[];foreach($xml->sheetData->row as$row){$cells=[];foreach($row->c as$c){$ref=(string)$c['r'];preg_match('/^([A-Z]+)/',$ref,$m);$col=$m[1]??'';$value='';$type=(string)$c['t'];if($type==='inlineStr')$value=(string)$c->is->t;else{$v=(string)$c->v;$value=$type==='s'?($shared[(int)$v]??''):$v;}$cells[$col]=trim($value);}if($cells)$rows[]=$cells;}if(!$rows)academy_json(['ok'=>true,'questions'=>[]]);$questions=[];$start=0;$first=$rows[0];$joined=mb_strtolower(implode(' ',array_values($first)));if(str_contains($joined,'السؤال')||str_contains($joined,'question'))$start=1;for($i=$start;$i<count($rows)&&count($questions)<100;$i++){$r=$rows[$i];$text=trim((string)($r['A']??''));if($text==='')continue;$opts=[];foreach(['B','C','D','E']as$col)if(isset($r[$col])&&trim((string)$r[$col])!=='')$opts[]=trim((string)$r[$col]);if(count($opts)<2)continue;$answer=trim((string)($r['F']??''));$correct=0;$answerValid=false;if($answer!==''){if(ctype_digit($answer)){$n=(int)$answer;$candidate=$n>0?$n-1:$n;if($candidate>=0&&$candidate<count($opts)){$correct=$candidate;$answerValid=true;}}else{$upper=strtoupper($answer);$map=['A'=>0,'B'=>1,'C'=>2,'D'=>3,'أ'=>0,'ا'=>0,'ب'=>1,'ج'=>2,'د'=>3];if(isset($map[$upper])&&$map[$upper]<count($opts)){$correct=$map[$upper];$answerValid=true;}else{foreach($opts as$j=>$o)if(trim($o)===$answer){$correct=$j;$answerValid=true;break;}}}}$questions[]=['text'=>mb_substr($text,0,500),'opts'=>array_map(fn($x)=>mb_substr($x,0,250),$opts),'correctAnswer'=>$correct,'explanation'=>mb_substr(trim((string)($r['G']??'')),0,1200),'skill'=>mb_substr(trim((string)($r['H']??'')),0,140),'difficulty'=>max(1,min(3,(int)($r['I']??2))),'_needsReview'=>!$answerValid];}academy_audit($u['id'],'teacher.questions.import_xlsx',null,['count'=>count($questions)]);academy_json(['ok'=>true,'questions'=>$questions]);}finally{$zip->close();@unlink($tmp);}
 }
 if($route==='/student/profile/save'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   academy_rate_limit('student-profile-'.$u['id'],30,3600);
   $b=academy_body();$name=trim((string)($b['name']??''));$type=(string)($b['educationType']??'');$stage=(string)($b['stage']??'');$grade=(string)($b['grade']??'');$avatarId=(string)($b['avatarId']??'');
   $max=$stage==='primary'?6:(in_array($stage,['prep','sec'],true)?3:0);
   if($name===''||mb_strlen($name)>100||!in_array($type,['public','azhar'],true)||$max===0||!ctype_digit($grade)||(int)$grade<1||(int)$grade>$max||!preg_match('/^student-(0[1-9]|1[0-9]|20)$/',$avatarId))academy_json(['ok'=>false,'error'=>'invalid_student_profile'],422);
   $uid=$u['id'];$root='studentProfilesV3/'.$uid;$old=academy_read_node($root);if(!is_array($old))$old=[];
   foreach(['name'=>$name,'educationType'=>$type,'stage'=>$stage,'grade'=>$grade,'avatarId'=>$avatarId,'updatedAt'=>academy_now_ms()] as $key=>$value)academy_write_node($root.'/'.$key,$value,$uid);
   if(!isset($old['createdAt']))academy_write_node($root.'/createdAt',academy_now_ms(),$uid);
   academy_audit($uid,'student.profile.update',$root,['educationType'=>$type,'stage'=>$stage,'grade'=>$grade]);
   academy_json(['ok'=>true,'profile'=>['name'=>$name,'educationType'=>$type,'stage'=>$stage,'grade'=>$grade,'avatarId'=>$avatarId]]);
 }
 if($route==='/teacher/profile/save'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$raw=is_array($b['profile']??null)?$b['profile']:[];$profile=['name'=>mb_substr(trim((string)($raw['name']??$u['display_name'])),0,80),'title'=>mb_substr(trim((string)($raw['title']??'')),0,100),'photoUrl'=>mb_substr(trim((string)($raw['photoUrl']??'')),0,500),'coverUrl'=>mb_substr(trim((string)($raw['coverUrl']??'')),0,500),'bio'=>mb_substr(trim((string)($raw['bio']??'')),0,1200),'qualifications'=>mb_substr(trim((string)($raw['qualifications']??'')),0,200),'experience'=>mb_substr(trim((string)($raw['experience']??'')),0,200),'teachingStyle'=>mb_substr(trim((string)($raw['teachingStyle']??'')),0,450)];if($profile['name']===''||$profile['title']==='')academy_json(['ok'=>false,'error'=>'profile_required'],422);foreach(['photoUrl','coverUrl']as$k)if($profile[$k]!==''&&!preg_match('#^https?://#i',$profile[$k]))academy_json(['ok'=>false,'error'=>'profile_url_invalid'],422);$now=academy_now_ms();$sid=substr(str_replace('-','',academy_uuid()),0,22);$submission=['type'=>'profile','submissionKind'=>'profile','profile'=>$profile,'status'=>'pending','teacherId'=>$u['id'],'teacherName'=>$profile['name'],'createdAt'=>$now];academy_write_node('teacherSubmissions/'.$u['id'].'/'.$sid,$submission,$u['id']);academy_audit($u['id'],'teacher_profile.submit',$sid,['direct'=>false]);academy_json(['ok'=>true,'published'=>false,'submissionId'=>$sid]);
 }
 /* V6 multi-teacher lesson content */
 if($route==='/content/lesson-teachers'&&$method==='GET'){
   $user=academy_current_user(false);$lessonId=trim((string)($_GET['lessonId']??''));if($lessonId==='')academy_json(['ok'=>false,'error'=>'lesson_required'],422);
   $lesson=academy_read_node('lessons/'.$lessonId);if(!is_array($lesson)||($lesson['isHidden']??false)===true)academy_json(['ok'=>false,'error'=>'lesson_not_found'],404);
   $packages=academy_read_node('teacherContentsV6/'.$lessonId);if(!is_array($packages))$packages=[];
   $legacy=academy_legacy_teacher_packages($lessonId,$lesson);foreach($legacy as$tid=>$pkg)if(!isset($packages[$tid]))$packages[$tid]=$pkg;
   $safe=[];$profiles=academy_public_teacher_profiles();foreach($packages as$tid=>$pkg){if(!is_array($pkg))continue;$row=academy_public_teacher_package($lessonId,(string)$tid,$pkg,$user,$lesson);if($row!==null)$safe[(string)$tid]=$row;}
   $teacherProfiles=[];foreach(array_keys($safe)as$tid)if(isset($profiles[$tid]))$teacherProfiles[$tid]=$profiles[$tid];
   $default=(string)($lesson['defaultTeacherId']??'');if($default===''||!isset($safe[$default]))$default=(string)(array_key_first($safe)??'');
   academy_json(['ok'=>true,'lessonId'=>$lessonId,'defaultTeacherId'=>$default,'packages'=>$safe,'teachers'=>$teacherProfiles]);
 }
 if($route==='/teacher/lesson-content'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$lessonId=trim((string)($_GET['lessonId']??''));
   $lesson=academy_read_node('lessons/'.$lessonId);if(!is_array($lesson))academy_json(['ok'=>false,'error'=>'lesson_not_found'],404);if(!academy_teacher_scope_allowed($u['id'],$lesson))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $packages=academy_read_node('teacherContentsV6/'.$lessonId);if(!is_array($packages))$packages=[];$legacy=academy_legacy_teacher_packages($lessonId,$lesson);foreach($legacy as$tid=>$pkg)if(!isset($packages[$tid]))$packages[$tid]=$pkg;
   $out=[];foreach($packages as$tid=>$pkg){if(!is_array($pkg))continue;$tid=(string)$tid;if($tid!==$u['id']&&(($pkg['status']??'published')!=='published'||academy_teacher_is_archived($tid)))continue;$pkg['editable']=$tid===$u['id'];$pkg['teacherId']=$tid;$out[$tid]=$pkg;}
   academy_json(['ok'=>true,'lesson'=>array_intersect_key($lesson,array_flip(['title','type','stage','grade','subject','unit','isFree','defaultTeacherId'])),'packages'=>$out,'teachers'=>academy_public_teacher_profiles()]);
 }
 if($route==='/teacher/content/list'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher')academy_json(['ok'=>false,'error'=>'forbidden'],403);$all=academy_read_node('teacherContentsV6');$mine=[];
   if(is_array($all))foreach($all as$lessonId=>$packages)if(is_array($packages)&&isset($packages[$u['id']])&&is_array($packages[$u['id']])){$lesson=academy_read_node('lessons/'.(string)$lessonId);$mine[(string)$lessonId]=array_merge($packages[$u['id']],['lessonId'=>(string)$lessonId,'lessonTitle'=>is_array($lesson)?($lesson['title']??'درس'):'درس']);}
   academy_json(['ok'=>true,'items'=>$mine,'permissions'=>academy_teacher_permissions($u['id'])]);
 }
 if($route==='/teacher/content/lesson'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$lessonId=trim((string)($b['lessonId']??''));$base=is_array($b['lesson']??null)?$b['lesson']:[];$pkg=is_array($b['package']??null)?$b['package']:[];
   $existingLesson=$lessonId!==''?academy_read_node('lessons/'.$lessonId):null;$scope=is_array($existingLesson)?$existingLesson:$base;$scope=['type'=>(string)($scope['type']??'public'),'stage'=>(string)($scope['stage']??''),'grade'=>(string)($scope['grade']??''),'subject'=>(string)($scope['subject']??'')]+$scope;
   if($scope['stage']===''||$scope['grade']===''||$scope['subject']===''||!academy_teacher_scope_allowed($u['id'],$scope))academy_json(['ok'=>false,'error'=>'assignment_mismatch'],403);
   $title=trim((string)($existingLesson['title']??$base['title']??''));if($title==='')academy_json(['ok'=>false,'error'=>'title_required'],422);
   $videos=[];foreach(academy_list_values($pkg['videos']??[])as$v){if(!is_array($v))continue;$url=trim((string)($v['url']??''));if($url==='')continue;if(!preg_match('#^https?://(www\.|m\.)?(youtube\.com|youtu\.be)/#i',$url))academy_json(['ok'=>false,'error'=>'video_invalid'],422);$videos[]=['url'=>$url,'title'=>mb_substr(trim((string)($v['title']??'')),0,160),'checkpoints'=>academy_list_values($v['checkpoints']??[])];if(count($videos)>=12)break;}
   $content=mb_substr((string)($pkg['content']??''),0,60000);$practice=academy_normalize_questions($pkg['practiceQuestions']??$pkg['questions']??[],100);$files=[];foreach(academy_list_values($pkg['files']??[])as$f){if(!is_array($f))continue;$url=trim((string)($f['url']??''));$name=mb_substr(trim((string)($f['name']??$f['title']??'ملف')),0,160);if($url!==''&&preg_match('#^https?://#i',$url))$files[]=['name'=>$name,'url'=>$url,'type'=>mb_substr((string)($f['type']??''),0,40)];if(count($files)>=20)break;}
   if(!$videos&&trim(strip_tags($content))===''&&!$practice&&!$files)academy_json(['ok'=>false,'error'=>'content_required'],422);
   $teacher=academy_read_node('teacherProfiles/'.$u['id']);$now=academy_now_ms();$package=['teacherId'=>$u['id'],'teacherName'=>$teacher['name']??$u['display_name'],'content'=>$content,'contentFormat'=>'html','imageUrl'=>trim((string)($pkg['imageUrl']??'')),'imagePosition'=>($pkg['imagePosition']??'top')==='bottom'?'bottom':'top','videos'=>$videos,'practiceQuestions'=>$practice,'files'=>$files,'notes'=>mb_substr(trim((string)($pkg['notes']??'')),0,2000),'active'=>true,'updatedAt'=>$now];
   $perms=academy_teacher_permissions($u['id']);$existingPackage=$lessonId!==''?academy_read_node('teacherContentsV6/'.$lessonId.'/'.$u['id']):null;$lessonDirect=($perms['publishLessons']??false)===true||(is_array($existingPackage)&&($perms['publishEdits']??false)===true);$filesDirect=!$files||($perms['publishFiles']??false)===true||(is_array($existingPackage)&&($perms['publishEdits']??false)===true);$direct=$lessonDirect&&$filesDirect;
   if(!$direct){$sid=substr(str_replace('-','',academy_uuid()),0,22);$submission=['submissionKind'=>'teacherContentV6','status'=>'pending','teacherId'=>$u['id'],'teacherName'=>$teacher['name']??$u['display_name'],'lessonId'=>$lessonId,'lessonBase'=>['title'=>$title,'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>(string)$scope['grade'],'subject'=>$scope['subject'],'subjectName'=>$base['subjectName']??$scope['subject'],'unit'=>(int)($scope['unit']??$base['unit']??1),'isFree'=>($base['isFree']??false)===true],'package'=>$package,'title'=>$title,'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>(string)$scope['grade'],'subject'=>$scope['subject'],'subjectName'=>$base['subjectName']??$scope['subject'],'createdAt'=>$now];academy_write_node('teacherSubmissions/'.$u['id'].'/'.$sid,$submission,$u['id']);academy_audit($u['id'],'teacher_content.submit',$lessonId?:$sid,['direct'=>false]);academy_json(['ok'=>true,'published'=>false,'submissionId'=>$sid]);}
   if($lessonId===''){$lessonId=substr(str_replace('-','',academy_uuid()),0,22);$lesson=['title'=>$title,'type'=>$scope['type'],'stage'=>$scope['stage'],'grade'=>(string)$scope['grade'],'subject'=>$scope['subject'],'unit'=>(int)($scope['unit']??$base['unit']??1),'isFree'=>($base['isFree']??false)===true,'isHidden'=>false,'workflowStatus'=>'published','reviewStatus'=>'approved','defaultTeacherId'=>$u['id'],'teacherIds'=>[$u['id']=>true],'hasTeacherContentV6'=>true,'createdAt'=>$now,'updatedAt'=>$now];academy_write_node('lessons/'.$lessonId,$lesson,$u['id']);}
   $package['lessonId']=$lessonId;$package['status']='published';$package['publishedAt']=$now;$package['createdAt']=is_array($existingPackage)?($existingPackage['createdAt']??$now):$now;if(is_array($existingPackage)&&isset($existingPackage['quiz']))$package['quiz']=$existingPackage['quiz'];academy_write_node('teacherContentsV6/'.$lessonId.'/'.$u['id'],$package,$u['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$u['id'],true,$u['id']);academy_write_node('lessons/'.$lessonId.'/hasTeacherContentV6',true,$u['id']);$default=academy_read_node('lessons/'.$lessonId.'/defaultTeacherId');if(!$default)academy_write_node('lessons/'.$lessonId.'/defaultTeacherId',$u['id'],$u['id']);academy_audit($u['id'],'teacher_content.publish',$lessonId,['direct'=>true]);academy_json(['ok'=>true,'published'=>true,'lessonId'=>$lessonId,'package'=>$package],201);
 }
 if($route==='/teacher/content/quiz'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='teacher'||!academy_teacher_is_active_profile($u['id']))academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$lessonId=trim((string)($b['lessonId']??''));$lesson=academy_read_node('lessons/'.$lessonId);if(!is_array($lesson)||!academy_teacher_scope_allowed($u['id'],$lesson))academy_json(['ok'=>false,'error'=>'lesson_not_allowed'],403);$questions=academy_normalize_questions($b['questions']??[],100);if(!$questions)academy_json(['ok'=>false,'error'=>'questions_required'],422);$title=mb_substr(trim((string)($b['title']??'اختبار الدرس')),0,160);$teacher=academy_read_node('teacherProfiles/'.$u['id']);$quiz=['title'=>$title,'questions'=>$questions,'teacherId'=>$u['id'],'teacherName'=>$teacher['name']??$u['display_name'],'updatedAt'=>academy_now_ms(),'isFree'=>($b['isFree']??($lesson['isFree']??false))===true,'active'=>true];$perms=academy_teacher_permissions($u['id']);$direct=($perms['publishQuizzes']??false)===true||(($perms['publishEdits']??false)===true&&is_array(academy_read_node('teacherContentsV6/'.$lessonId.'/'.$u['id'].'/quiz')));
   if(!$direct){$sid=substr(str_replace('-','',academy_uuid()),0,22);$submission=['submissionKind'=>'teacherQuizV6','status'=>'pending','teacherId'=>$u['id'],'teacherName'=>$teacher['name']??$u['display_name'],'lessonId'=>$lessonId,'title'=>$title,'quiz'=>$quiz,'type'=>$lesson['type']??'public','stage'=>$lesson['stage']??'','grade'=>(string)($lesson['grade']??''),'subject'=>$lesson['subject']??'','createdAt'=>academy_now_ms()];academy_write_node('teacherSubmissions/'.$u['id'].'/'.$sid,$submission,$u['id']);academy_audit($u['id'],'teacher_quiz.submit',$lessonId,['direct'=>false]);academy_json(['ok'=>true,'published'=>false,'submissionId'=>$sid]);}
   $path='teacherContentsV6/'.$lessonId.'/'.$u['id'];$package=academy_read_node($path);if(!is_array($package))$package=['lessonId'=>$lessonId,'teacherId'=>$u['id'],'teacherName'=>$teacher['name']??$u['display_name'],'status'=>'published','active'=>true,'content'=>'','videos'=>[],'practiceQuestions'=>[],'createdAt'=>academy_now_ms()];$package['quiz']=$quiz;$package['status']='published';$package['updatedAt']=academy_now_ms();academy_write_node($path,$package,$u['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$u['id'],true,$u['id']);academy_write_node('lessons/'.$lessonId.'/hasTeacherContentV6',true,$u['id']);academy_audit($u['id'],'teacher_quiz.publish',$lessonId,['direct'=>true,'questions'=>count($questions)]);academy_json(['ok'=>true,'published'=>true,'lessonId'=>$lessonId,'quiz'=>$quiz]);
 }
 if($route==='/admin/teacher-submissions/decision'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=trim((string)($b['teacherId']??''));$sid=trim((string)($b['submissionId']??''));$decision=(string)($b['decision']??'');if(!in_array($decision,['approve','reject'],true))academy_json(['ok'=>false,'error'=>'decision_invalid'],422);$s=academy_read_node('teacherSubmissions/'.$uid.'/'.$sid);if(!is_array($s)||($s['status']??'pending')!=='pending')academy_json(['ok'=>false,'error'=>'submission_unavailable'],404);if(!in_array($s['submissionKind']??'',['teacherContentV6','teacherQuizV6','profile'],true))academy_json(['ok'=>false,'error'=>'unsupported_submission'],422);$now=academy_now_ms();if($decision==='reject'){academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/status','rejected',$admin['id']);academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/reviewedAt',$now,$admin['id']);academy_audit($admin['id'],'teacher_submission.reject',$sid,['teacherUid'=>$uid,'kind'=>$s['submissionKind']]);academy_json(['ok'=>true,'status'=>'rejected']);}
   if(!academy_teacher_is_active_profile($uid))academy_json(['ok'=>false,'error'=>'teacher_inactive'],409);
   if(($s['submissionKind']??'')==='profile'){
     $update=is_array($s['profile']??null)?$s['profile']:[];
     $allowed=['name','title','photoUrl','coverUrl','bio','qualifications','experience','teachingStyle'];$safe=[];
     foreach($allowed as $k)$safe[$k]=mb_substr(trim((string)($update[$k]??'')),0,$k==='bio'?1200:($k==='teachingStyle'?450:(in_array($k,['photoUrl','coverUrl'],true)?500:200)));
     if($safe['name']===''||$safe['title']==='')academy_json(['ok'=>false,'error'=>'profile_required'],422);
     foreach(['photoUrl','coverUrl'] as $k)if($safe[$k]!==''&&!preg_match('#^https?://#i',$safe[$k]))academy_json(['ok'=>false,'error'=>'profile_url_invalid'],422);
     $current=academy_read_node('settings/publicTeachers/'.$uid);if(!is_array($current))$current=[];
     academy_write_node('settings/publicTeachers/'.$uid,array_merge($current,$safe,['active'=>true,'updatedAt'=>$now]),$admin['id']);
     academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/status','approved',$admin['id']);
     academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/reviewedAt',$now,$admin['id']);
     academy_audit($admin['id'],'teacher_profile.approve',$sid,['teacherUid'=>$uid]);academy_json(['ok'=>true,'status'=>'approved','teacherId'=>$uid]);
   }
   $lessonId=(string)($s['lessonId']??'');
   if(($s['submissionKind']??'')==='teacherContentV6'){$base=is_array($s['lessonBase']??null)?$s['lessonBase']:[];if($lessonId===''){$lessonId=substr(str_replace('-','',academy_uuid()),0,22);$lesson=['title'=>$base['title']??$s['title']??'درس','type'=>$base['type']??$s['type']??'public','stage'=>$base['stage']??$s['stage']??'','grade'=>(string)($base['grade']??$s['grade']??''),'subject'=>$base['subject']??$s['subject']??'','unit'=>(int)($base['unit']??1),'isFree'=>($base['isFree']??false)===true,'isHidden'=>false,'workflowStatus'=>'published','reviewStatus'=>'approved','defaultTeacherId'=>$uid,'teacherIds'=>[$uid=>true],'hasTeacherContentV6'=>true,'createdAt'=>$now,'updatedAt'=>$now];academy_write_node('lessons/'.$lessonId,$lesson,$admin['id']);}$pkg=is_array($s['package']??null)?$s['package']:[];$pkg['lessonId']=$lessonId;$pkg['teacherId']=$uid;$pkg['status']='published';$pkg['active']=true;$pkg['publishedAt']=$now;$pkg['updatedAt']=$now;$old=academy_read_node('teacherContentsV6/'.$lessonId.'/'.$uid);$pkg['createdAt']=is_array($old)?($old['createdAt']??$now):$now;if(is_array($old)&&isset($old['quiz'])&&!isset($pkg['quiz']))$pkg['quiz']=$old['quiz'];academy_write_node('teacherContentsV6/'.$lessonId.'/'.$uid,$pkg,$admin['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$uid,true,$admin['id']);academy_write_node('lessons/'.$lessonId.'/hasTeacherContentV6',true,$admin['id']);academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/lessonId',$lessonId,$admin['id']);}
   else{$lesson=academy_read_node('lessons/'.$lessonId);if(!is_array($lesson))academy_json(['ok'=>false,'error'=>'lesson_not_found'],404);$path='teacherContentsV6/'.$lessonId.'/'.$uid;$pkg=academy_read_node($path);$teacher=academy_read_node('teacherProfiles/'.$uid);if(!is_array($pkg))$pkg=['lessonId'=>$lessonId,'teacherId'=>$uid,'teacherName'=>$teacher['name']??'مدرس','content'=>'','videos'=>[],'practiceQuestions'=>[],'createdAt'=>$now];$pkg['quiz']=$s['quiz']??[];$pkg['status']='published';$pkg['active']=true;$pkg['updatedAt']=$now;academy_write_node($path,$pkg,$admin['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$uid,true,$admin['id']);}
   academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/status','approved',$admin['id']);academy_write_node('teacherSubmissions/'.$uid.'/'.$sid.'/reviewedAt',$now,$admin['id']);academy_audit($admin['id'],'teacher_submission.approve',$sid,['teacherUid'=>$uid,'kind'=>$s['submissionKind'],'lessonId'=>$lessonId]);academy_json(['ok'=>true,'status'=>'approved','lessonId'=>$lessonId]);
 }
 if($route==='/admin/lessons/default-teacher'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$lessonId=trim((string)($b['lessonId']??''));$teacherId=trim((string)($b['teacherId']??''));$lesson=academy_read_node('lessons/'.$lessonId);$pkg=academy_read_node('teacherContentsV6/'.$lessonId.'/'.$teacherId);if(!is_array($lesson))academy_json(['ok'=>false,'error'=>'teacher_package_unavailable'],422);if(!is_array($pkg)){$legacy=academy_legacy_teacher_packages($lessonId,$lesson);$pkg=$legacy[$teacherId]??null;}if(!is_array($pkg)||($pkg['status']??'published')!=='published'||($pkg['active']??true)===false||academy_teacher_is_archived($teacherId))academy_json(['ok'=>false,'error'=>'teacher_package_unavailable'],422);academy_write_node('lessons/'.$lessonId.'/defaultTeacherId',$teacherId,$admin['id']);academy_audit($admin['id'],'lesson.default_teacher.update',$lessonId,['teacherId'=>$teacherId]);academy_json(['ok'=>true,'lessonId'=>$lessonId,'teacherId'=>$teacherId]);
 }
 if($route==='/admin/teacher-content/visibility'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$lessonId=trim((string)($b['lessonId']??''));$teacherId=trim((string)($b['teacherId']??''));$active=($b['active']??true)===true;$pkg=academy_read_node('teacherContentsV6/'.$lessonId.'/'.$teacherId);if(!is_array($pkg))academy_json(['ok'=>false,'error'=>'teacher_package_not_found'],404);academy_write_node('teacherContentsV6/'.$lessonId.'/'.$teacherId.'/active',$active,$admin['id']);academy_write_node('teacherContentsV6/'.$lessonId.'/'.$teacherId.'/visibilityUpdatedAt',academy_now_ms(),$admin['id']);academy_write_node('teacherContentsV6/'.$lessonId.'/'.$teacherId.'/visibilityUpdatedBy',$admin['id'],$admin['id']);if(!$active){$default=academy_read_node('lessons/'.$lessonId.'/defaultTeacherId');if((string)$default===$teacherId)academy_write_node('lessons/'.$lessonId.'/defaultTeacherId',null,$admin['id']);}academy_audit($admin['id'],$active?'teacher_content.show':'teacher_content.hide',$lessonId,['teacherId'=>$teacherId]);academy_json(['ok'=>true,'lessonId'=>$lessonId,'teacherId'=>$teacherId,'active'=>$active]);
 }
 if($route==='/admin/teachers/permissions'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=trim((string)($b['teacherId']??''));$profile=academy_read_node('teacherProfiles/'.$uid);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'teacher_not_found'],404);$allowed=['publishLessons','publishQuizzes','publishFiles','publishProfile','publishEdits','createGroups','shareContent','createChallenges','publishChallenges','publishQuestions','createTournaments','publishTournaments','createLiveSessions','publishLiveSessions'];$next=academy_teacher_permissions($uid);foreach($allowed as$k)if(array_key_exists($k,$b))$next[$k]=(bool)$b[$k];academy_write_node('teacherProfiles/'.$uid.'/permissions',$next,$admin['id']);academy_audit($admin['id'],'teacher.permissions.update',$uid,$next);academy_json(['ok'=>true,'permissions'=>$next]);
 }
 if($route==='/admin/teachers/archive'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=trim((string)($b['teacherId']??''));$reason=mb_substr(trim((string)($b['reason']??'')),0,500);$profile=academy_read_node('teacherProfiles/'.$uid);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'teacher_not_found'],404);$now=academy_now_ms();$pdo->prepare("UPDATE academy_users SET status='disabled' WHERE id=? AND primary_role='teacher'")->execute([$uid]);$pdo->prepare('UPDATE academy_sessions SET revoked_at=UTC_TIMESTAMP() WHERE user_id=?')->execute([$uid]);academy_write_node('teacherProfiles/'.$uid.'/isActive',false,$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/accountState','archived',$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/isArchived',true,$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/archiveInfo',['archivedAt'=>$now,'archivedBy'=>$admin['id'],'reason'=>$reason],$admin['id']);$public=academy_read_node('settings/publicTeachers/'.$uid);if(is_array($public))academy_write_node('settings/publicTeachers/'.$uid.'/active',false,$admin['id']);academy_audit($admin['id'],'teacher.archive',$uid,['reason'=>$reason]);academy_json(['ok'=>true,'teacherId'=>$uid,'state'=>'archived']);
 }
 if($route==='/admin/teachers/restore'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$uid=trim((string)($b['teacherId']??''));$profile=academy_read_node('teacherProfiles/'.$uid);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'teacher_not_found'],404);$pdo->prepare("UPDATE academy_users SET status='active' WHERE id=? AND primary_role='teacher'")->execute([$uid]);academy_write_node('teacherProfiles/'.$uid.'/isActive',true,$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/accountState','active',$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/isArchived',false,$admin['id']);academy_write_node('teacherProfiles/'.$uid.'/restoreInfo',['restoredAt'=>academy_now_ms(),'restoredBy'=>$admin['id']],$admin['id']);$public=academy_read_node('settings/publicTeachers/'.$uid);if(is_array($public))academy_write_node('settings/publicTeachers/'.$uid.'/active',true,$admin['id']);academy_audit($admin['id'],'teacher.restore',$uid);academy_json(['ok'=>true,'teacherId'=>$uid,'state'=>'active']);
 }
 if($route==='/admin/teachers/transfer-content'&&$method==='POST'){
   $admin=academy_current_user(true);if($admin['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$source=trim((string)($b['sourceTeacherId']??''));$target=trim((string)($b['targetTeacherId']??''));$move=($b['move']??false)===true;if($source===''||$target===''||$source===$target)academy_json(['ok'=>false,'error'=>'teacher_ids_invalid'],422);
   $sourceP=academy_read_node('teacherProfiles/'.$source);$targetP=academy_read_node('teacherProfiles/'.$target);if(!is_array($sourceP)||!is_array($targetP)||academy_teacher_is_archived($target)||($targetP['isActive']??true)===false)academy_json(['ok'=>false,'error'=>'teacher_unavailable'],404);
   $all=academy_read_node('teacherContentsV6');if(!is_array($all))$all=[];$lessonsAll=academy_read_node('lessons');if(!is_array($lessonsAll))$lessonsAll=[];$lessonIds=array_unique(array_merge(array_keys($all),array_keys($lessonsAll)));$count=0;$now=academy_now_ms();
   foreach($lessonIds as$lessonId){$lesson=is_array($lessonsAll[$lessonId]??null)?$lessonsAll[$lessonId]:academy_read_node('lessons/'.(string)$lessonId);if(!is_array($lesson))continue;$sourceWasV6=is_array($all[$lessonId][$source]??null);$sourcePackage=$sourceWasV6?$all[$lessonId][$source]:null;if(!is_array($sourcePackage)){$legacy=academy_legacy_teacher_packages((string)$lessonId,$lesson);$sourcePackage=$legacy[$source]??null;}if(!is_array($sourcePackage))continue;
     $copy=$sourcePackage;unset($copy['legacy']);$copy['lessonId']=(string)$lessonId;$copy['teacherId']=$target;$copy['teacherName']=$targetP['name']??'مدرس';$copy['originalTeacherId']=$source;$copy['transferredAt']=$now;$copy['transferredBy']=$admin['id'];$copy['status']='published';$copy['active']=true;$copy['updatedAt']=$now;if(empty($copy['createdAt']))$copy['createdAt']=$now;academy_write_node('teacherContentsV6/'.$lessonId.'/'.$target,$copy,$admin['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$target,true,$admin['id']);academy_write_node('lessons/'.$lessonId.'/hasTeacherContentV6',true,$admin['id']);
     $assignment=['type'=>$lesson['type']??'public','stage'=>$lesson['stage']??'','grade'=>(string)($lesson['grade']??''),'subject'=>$lesson['subject']??'','subjectName'=>$lesson['subjectName']??($lesson['subject']??''),'createdAt'=>$now];if(!academy_teacher_scope_allowed($target,$lesson)){$assignments=$targetP['assignments']??[];if(!is_array($assignments))$assignments=[];$assignments['transfer-'.$lessonId]=$assignment;academy_write_node('teacherProfiles/'.$target.'/assignments',$assignments,$admin['id']);$targetP['assignments']=$assignments;}
     if($move){if($sourceWasV6)academy_write_node('teacherContentsV6/'.$lessonId.'/'.$source,null,$admin['id']);else academy_write_node('lessons/'.$lessonId.'/legacyTeacherContentDisabled/'.$source,true,$admin['id']);academy_write_node('lessons/'.$lessonId.'/teacherIds/'.$source,null,$admin['id']);$default=(string)($lesson['defaultTeacherId']??'');if($default===$source)academy_write_node('lessons/'.$lessonId.'/defaultTeacherId',$target,$admin['id']);if(!$sourceWasV6){$quizzes=academy_read_node('quizzes');if(is_array($quizzes))foreach($quizzes as$qid=>$q)if(is_array($q)&&($q['lessonId']??'')===(string)$lessonId&&(string)($q['teacherId']??($lesson['teacherId']??''))===$source)academy_write_node('quizzes/'.$qid.'/isHidden',true,$admin['id']);$files=academy_read_node('files');if(is_array($files))foreach($files as$fid=>$f)if(is_array($f)&&($f['lessonId']??'')===(string)$lessonId&&(string)($f['teacherId']??($lesson['teacherId']??''))===$source)academy_write_node('files/'.$fid.'/isHidden',true,$admin['id']);}}
     $count++;
   }
   academy_audit($admin['id'],'teacher.content.transfer',$source,['target'=>$target,'move'=>$move,'count'=>$count]);academy_json(['ok'=>true,'count'=>$count,'move'=>$move]);
 }
 if($route==='/certificates/issue'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$type=(string)($b['type']??'public');$stage=(string)($b['stage']??'');$grade=(string)($b['grade']??'');$subject=(string)($b['subject']??'');if($subject==='')academy_json(['ok'=>false,'error'=>'subject_required'],422);$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($profile))academy_json(['ok'=>false,'error'=>'profile_missing'],422);$pct=(float)($profile['subjectProgressV3'][$type][$stage][$grade][$subject]??($profile['subjectProgress'][$subject]??0));if($pct<100)academy_json(['ok'=>false,'error'=>'subject_not_completed','progress'=>$pct],422);$raw=$u['id'].'-'.$type.'-'.$stage.'-'.$grade.'-'.$subject;$safe=preg_replace('/[^a-zA-Z0-9_-]/','-',$raw);$id='ACD-'.strtoupper(substr($safe,0,72));$existing=academy_read_node('certificatesV4/'.$id);$cert=['id'=>$id,'studentId'=>$u['id'],'studentName'=>$profile['name']??$u['display_name'],'type'=>$type,'stage'=>$stage,'grade'=>$grade,'subject'=>$subject,'subjectName'=>$b['subjectName']??$subject,'score'=>(float)($b['score']??100),'valid'=>true,'issuedAt'=>is_array($existing)?($existing['issuedAt']??academy_now_ms()):academy_now_ms(),'updatedAt'=>academy_now_ms()];academy_write_node('certificatesV4/'.$id,array_merge(is_array($existing)?$existing:[],$cert),$u['id']);academy_audit($u['id'],'certificate.issue',$id);academy_json(['ok'=>true,'id'=>$id,'certificate'=>$cert]);
 }
 if($route==='/certificates/verify'&&$method==='GET'){
   $id=strtoupper(trim((string)($_GET['id']??'')));if($id==='')academy_json(['ok'=>false,'error'=>'certificate_required'],422);$c=academy_read_node('certificatesV4/'.$id);if(!is_array($c)||($c['valid']??true)===false)academy_json(['ok'=>true,'certificate'=>null]);$public=['id'=>$c['id']??$id,'studentName'=>$c['studentName']??'','subjectName'=>$c['subjectName']??($c['subject']??''),'type'=>$c['type']??'','stage'=>$c['stage']??'','grade'=>$c['grade']??'','score'=>$c['score']??null,'issuedAt'=>$c['issuedAt']??null,'valid'=>true];academy_json(['ok'=>true,'certificate'=>$public]);
 }
 if($route==='/subscriptions/request'&&$method==='POST'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$b=academy_body();$planId=trim((string)($b['planId']??''));$plan=academy_read_node('subscriptionPlansV1/'.$planId);$profile=academy_read_node('studentProfilesV3/'.$u['id']);if(!is_array($plan)||($plan['isActive']??true)===false||!is_array($profile))academy_json(['ok'=>false,'error'=>'plan_unavailable'],404);
   if(!empty($plan['targetType'])&&$plan['targetType']!==($profile['educationType']??''))academy_json(['ok'=>false,'error'=>'plan_scope_mismatch'],422);if(!empty($plan['targetStage'])&&$plan['targetStage']!==($profile['stage']??''))academy_json(['ok'=>false,'error'=>'plan_scope_mismatch'],422);if(!empty($plan['targetGrade'])&&(string)$plan['targetGrade']!==(string)($profile['grade']??''))academy_json(['ok'=>false,'error'=>'plan_scope_mismatch'],422);
   $existing=academy_read_node('subscriptionRequestsV1/'.$u['id']);if(is_array($existing))foreach($existing as$r)if(is_array($r)&&($r['status']??'')==='pending')academy_json(['ok'=>false,'error'=>'pending_request_exists'],409);
   $couponCode=strtoupper(trim((string)($b['couponCode']??'')));$coupon=null;$discountPercent=0.0;$maxDiscount=0.0;$now=academy_now_ms();if($couponCode!==''){$coupon=academy_read_node('subscriptionCouponsV1/'.$couponCode);if(!is_array($coupon)||($coupon['active']??false)!==true||(!empty($coupon['expiresAt'])&&(int)$coupon['expiresAt']<$now)||(!empty($coupon['maxUses'])&&(int)($coupon['uses']??0)>=(int)$coupon['maxUses']))academy_json(['ok'=>false,'error'=>'coupon_invalid'],422);$discountPercent=max(0,min(100,(float)($coupon['discountPercent']??0)));$maxDiscount=max(0,(float)($coupon['maxDiscount']??0));}
   $allowedPaymentMethods=['','instapay','vodafone_cash','orange_cash','etisalat_cash','bank_transfer','cash','other'];$paymentMethod=trim((string)($b['paymentMethod']??''));if(!in_array($paymentMethod,$allowedPaymentMethods,true))academy_json(['ok'=>false,'error'=>'payment_method_invalid'],422);$paymentReference=trim((string)($b['paymentReference']??''));if(mb_strlen($paymentReference)>100)academy_json(['ok'=>false,'error'=>'payment_reference_too_long'],422);if($paymentReference!==''&&$paymentMethod==='')academy_json(['ok'=>false,'error'=>'payment_method_required'],422);
   $original=max(0,(float)($plan['price']??0));$discount=$original*$discountPercent/100;if($maxDiscount>0)$discount=min($discount,$maxDiscount);$final=max(0,$original-$discount);$id=substr(str_replace('-','',academy_uuid()),0,22);$request=['id'=>$id,'studentId'=>$u['id'],'studentName'=>$profile['name']??$u['display_name'],'studentPhone'=>$profile['phone']??'','planId'=>$planId,'planName'=>$plan['name']??'باقة','originalPrice'=>$original,'price'=>round($final,2),'discountAmount'=>round($discount,2),'discountPercent'=>$discountPercent,'couponCode'=>$couponCode,'paymentMethod'=>$paymentMethod,'paymentReference'=>$paymentReference,'durationDays'=>(int)($plan['durationDays']??30),'status'=>'pending','createdAt'=>$now,'updatedAt'=>$now];academy_write_node('subscriptionRequestsV1/'.$u['id'].'/'.$id,$request,$u['id']);academy_audit($u['id'],'subscription.request.create',$id,['planId'=>$planId,'couponCode'=>$couponCode,'paymentMethod'=>$paymentMethod]);academy_json(['ok'=>true,'request'=>$request],201);
 }
 if($route==='/subscriptions/coupon'&&$method==='GET'){
   $u=academy_current_user(true);if($u['primary_role']!=='student')academy_json(['ok'=>false,'error'=>'forbidden'],403);$code=strtoupper(trim((string)($_GET['code']??'')));if($code==='')academy_json(['ok'=>false,'error'=>'coupon_required'],422);$c=academy_read_node('subscriptionCouponsV1/'.$code);$now=academy_now_ms();if(!is_array($c)||($c['active']??false)!==true||(!empty($c['expiresAt'])&&(int)$c['expiresAt']<$now)||(!empty($c['maxUses'])&&(int)($c['uses']??0)>=(int)$c['maxUses']))academy_json(['ok'=>false,'error'=>'coupon_invalid'],404);academy_json(['ok'=>true,'coupon'=>['code'=>$code,'discountPercent'=>max(0,min(100,(float)($c['discountPercent']??0))),'maxDiscount'=>max(0,(float)($c['maxDiscount']??0)),'expiresAt'=>$c['expiresAt']??null]]);
 }


 // V33 — authenticated support tickets for students and guardians; the server supplies owner ID.
 if($route==='/account/support/v33'&&in_array($method,['GET','POST'],true)){
   $u=academy_current_user(true);
   if(!in_array($u['primary_role'],['parent','student'],true))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $uid=$u['id'];$root='supportTicketsV1/'.$uid;
   if($method==='GET'){
     $all=academy_read_node($root);$tickets=[];
     if(is_array($all))foreach($all as$id=>$t)if(is_array($t)){
       $t['id']=(string)$id;
       $tickets[]=$t;
     }
     usort($tickets,fn($a,$b)=>(int)($b['updatedAt']??$b['createdAt']??0)<=>(int)($a['updatedAt']??$a['createdAt']??0));
     academy_json(['ok'=>true,'tickets'=>array_slice($tickets,0,70)]);
   }
   academy_rate_limit('support-v33-'.$uid,30,3600);
   $b=academy_body();$action=(string)($b['action']??'');$now=academy_now_ms();
   if($action==='create'){
     $title=trim((string)($b['title']??''));$description=trim((string)($b['description']??''));$category=(string)($b['category']??'other');
     if(mb_strlen($title)<5||mb_strlen($title)>140||mb_strlen($description)<10||mb_strlen($description)>3000||!in_array($category,['technical','account','content','subscription','other'],true))academy_json(['ok'=>false,'error'=>'invalid_support_ticket'],422);
     $id=substr(str_replace('-','',academy_uuid()),0,24);
     $ticket=['id'=>$id,'ticketCode'=>strtoupper(substr($id,-6)),'requesterId'=>$uid,'requesterRole'=>$u['primary_role'],'requesterName'=>$u['display_name'],'category'=>$category,'title'=>$title,'description'=>$description,'status'=>'new','priority'=>'normal','createdAt'=>$now,'updatedAt'=>$now,'messages'=>[]];
     academy_write_node($root.'/'.$id,$ticket,$uid);
     academy_audit($uid,'support.ticket.create',$id,['category'=>$category]);academy_json(['ok'=>true,'id'=>$id],201);
   }
   if($action==='reply'){
     $id=(string)($b['ticketId']??'');$text=trim((string)($b['text']??''));
     if(!preg_match('/^[a-f0-9]{24}$/D',$id)||mb_strlen($text)<2||mb_strlen($text)>3000)academy_json(['ok'=>false,'error'=>'invalid_support_reply'],422);
     $ticket=academy_read_node($root.'/'.$id);
     if(!is_array($ticket)||($ticket['requesterId']??'')!==$uid)academy_json(['ok'=>false,'error'=>'not_found'],404);
     if(in_array($ticket['status']??'new',['resolved','closed'],true))academy_json(['ok'=>false,'error'=>'support_ticket_closed'],409);
     $mid=substr(str_replace('-','',academy_uuid()),0,24);
     academy_write_node($root.'/'.$id.'/messages/'.$mid,['role'=>$u['primary_role'],'actorId'=>$uid,'text'=>$text,'createdAt'=>$now],$uid);
     academy_write_node($root.'/'.$id.'/updatedAt',$now,$uid);
     academy_audit($uid,'support.ticket.reply',$id);academy_json(['ok'=>true,'messageId'=>$mid]);
   }
   academy_json(['ok'=>false,'error'=>'invalid_action'],422);
 }
 // Guardian may inspect an already linked child's subscription status, but cannot request or activate it.
 if($route==='/parent/child-subscription/v33'&&$method==='GET'){
   $u=academy_current_user(true);
   if($u['primary_role']!=='parent')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $sid=(string)($_GET['studentId']??'');
   if(!preg_match('/^[a-f0-9-]{36}$/D',$sid))academy_json(['ok'=>false,'error'=>'student_invalid'],422);
   if(!academy_parent_can_access_student($u['id'],$sid))academy_json(['ok'=>false,'error'=>'student_not_linked'],403);
   $current=academy_read_node('studentSubscriptionsV1/'.$sid);$requests=academy_read_node('subscriptionRequestsV1/'.$sid);$list=[];
   if(is_array($requests))foreach($requests as$r)if(is_array($r))$list[]=['planName'=>(string)($r['planName']??''),'status'=>(string)($r['status']??''),'createdAt'=>(int)($r['createdAt']??0)];
   usort($list,fn($a,$b)=>$b['createdAt']<=>$a['createdAt']);
   $current=is_array($current)?['status'=>$current['status']??'','planName'=>$current['planName']??'','planId'=>$current['planId']??'','endsAt'=>$current['endsAt']??0]:null;
   academy_json(['ok'=>true,'studentId'=>$sid,'current'=>$current,'requests'=>array_slice($list,0,30)]);
 }

 // V29/4: admin-only, read-only data-integrity dashboard. No PII returned.
 if($route==='/admin/diagnostics/v29'&&$method==='GET'){
   $u=academy_current_user(true);
   if($u['primary_role']!=='admin')academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $roots=['lessons','quizzes','files','studentProfilesV3','teacherProfiles','teacherSubmissions','settings/publicTeachers','learningV4/mastery','parentLinksV4'];
   $data=[];
   foreach($roots as $root){$value=academy_read_node($root);$data[$root]=is_array($value)?$value:[];}
   $lessons=$data['lessons'];$quizzes=$data['quizzes'];
   $embedded=0;$emptyQuiz=0;$orphaned=0;$missingVideo=0;$hidden=0;
   foreach($lessons as $lesson){
     if(!is_array($lesson))continue;
     if(($lesson['isHidden']??false)===true)$hidden++;
     $raw=$lesson['questions']??[];
     if(is_array($raw)&&count($raw)>0)$embedded++;
     $videos=$lesson['videos']??[];
     if((!is_array($videos)||count($videos)===0)&&empty($lesson['videoUrl'])&&empty($lesson['youtubeUrl'])&&empty($lesson['videoLink']))$missingVideo++;
   }
   foreach($quizzes as $quiz){
     if(!is_array($quiz))continue;
     $lessonId=(string)($quiz['lessonId']??'');
     if($lessonId===''||!isset($lessons[$lessonId]))$orphaned++;
     if(!is_array($quiz['questions']??null)||count($quiz['questions'])===0)$emptyQuiz++;
   }
   $pending=0;
   foreach($data['teacherSubmissions'] as $requests){
     if(!is_array($requests))continue;
     foreach($requests as $request)if(is_array($request)&&($request['status']??'')==='pending')$pending++;
   }
   $masteryStudents=0;
   foreach($data['learningV4/mastery'] as $mastery)if(is_array($mastery)&&count($mastery)>0)$masteryStudents++;
   $resultStudents=0;
   foreach($data['studentProfilesV3'] as $profile)if(is_array($profile)&&is_array($profile['quizResultsV22']??null)&&count($profile['quizResultsV22'])>0)$resultStudents++;
   $links=0;
   foreach($data['parentLinksV4'] as $parents)if(is_array($parents))$links+=count($parents);
   $publishedTeachers=0;
   foreach($data['settings/publicTeachers'] as $profile)if(is_array($profile)&&($profile['active']??true)!==false)$publishedTeachers++;
   academy_json(['ok'=>true,'generatedAt'=>gmdate('c'),
     'counts'=>['lessons'=>count($lessons),'quizzes'=>count($quizzes),'files'=>count($data['files']),
       'students'=>count($data['studentProfilesV3']),'teacherProfiles'=>count($data['teacherProfiles']),
       'publishedTeachers'=>$publishedTeachers,'pendingTeacherSubmissions'=>$pending,'parentLinks'=>$links],
     'checks'=>['orphanQuizzes'=>$orphaned,'emptyQuizzes'=>$emptyQuiz,'lessonsWithEmbeddedQuestions'=>$embedded,
       'lessonsWithoutDirectVideo'=>$missingVideo,'hiddenLessons'=>$hidden,
       'studentsWithLegacyMastery'=>$masteryStudents,'studentsWithNewQuizResults'=>$resultStudents],
     'notes'=>['resultsNotExams'=>'تقدم التعلم القديم لا يعني وجود نتيجة امتحان محفوظة',
       'directVideoOnly'=>'عدد الفيديوهات المفقودة لا يشمل مقاطع المعلمين المحفوظة في حزم مستقلة',
       'readOnly'=>'التقرير للقراءة فقط ولا يصحح أو يحذف أي بيانات']]);
 }

 if($route==='/data'&&in_array($method,['GET','PUT','DELETE'],true)){$b=$method==='GET'?[]:academy_body();$path=academy_path((string)($_GET['path']??($b['path']??'')));$u=academy_current_user(false);if(!academy_role_allows($u,$method,$path))academy_json(['ok'=>false,'error'=>$u?'forbidden':'auth_required'],$u?403:401);if($method==='GET'){ $value=academy_read_node($path);$value=academy_filter_read_response($u,$path,$value);academy_json(['ok'=>true,'path'=>$path,'value'=>$value]);}$value=$b['value']??null;$uid=$u['id']??null;
 if(($u['primary_role']??'')==='teacher'&&str_starts_with($path,'teacherSubmissions/'.$uid.'/')){
   if(!is_array($value)||($value['status']??'')!=='pending'||(isset($value['teacherId'])&&(string)$value['teacherId']!==$uid))academy_json(['ok'=>false,'error'=>'forbidden'],403);
 }
 try{academy_write_node($path,$method==='DELETE'?null:$value,$uid);}catch(RuntimeException $e){if($e->getMessage()==='academy_data_busy')academy_json(['ok'=>false,'error'=>'busy'],409);throw $e;}academy_audit($uid,$method==='DELETE'?'data.remove':'data.set',$path);academy_json(['ok'=>true,'path'=>$path,'value'=>$method==='DELETE'?null:$value]);}
 if($route==='/data/multi-update'&&$method==='POST'){$u=academy_current_user(true);$b=academy_body();$base=academy_path((string)($b['basePath']??''));$updates=$b['updates']??null;if(!is_array($updates))academy_json(['ok'=>false,'error'=>'object_required'],422);$resolved=[];foreach($updates as$k=>$v){$child=academy_path((string)$k);$path=$base===''?$child:($child===''?$base:$base.'/'.$child);if(!academy_role_allows($u,'PUT',$path))academy_json(['ok'=>false,'error'=>'forbidden','path'=>$path],403);if(($u['primary_role']??'')==='teacher'&&str_starts_with($path,'teacherSubmissions/'.$u['id'].'/'))academy_json(['ok'=>false,'error'=>'forbidden'],403);$resolved[$path]=$v;}try{$locks=academy_acquire_data_locks($pdo,array_keys($resolved));}catch(RuntimeException $e){if($e->getMessage()==='academy_data_busy')academy_json(['ok'=>false,'error'=>'busy'],409);throw $e;}try{$pdo->beginTransaction();try{foreach($resolved as$path=>$v){academy_delete_node_raw($pdo,$path);academy_insert_value_raw($pdo,$path,$v,$u['id']);}$pdo->commit();}catch(Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}}finally{academy_release_data_locks($pdo,$locks);}academy_audit($u['id'],'data.multi_update',$base,['count'=>count($resolved)]);academy_json(['ok'=>true,'count'=>count($resolved)]);}
 if($route==='/data/transaction'&&$method==='POST'){
   $u=academy_current_user(true);$b=academy_body();$path=academy_path((string)($b['path']??''));
   if(!academy_role_allows($u,'PUT',$path))academy_json(['ok'=>false,'error'=>'forbidden'],403);
   $expected=(string)($b['expectedHash']??'');
   try{$locks=academy_acquire_data_locks($pdo,[$path]);}catch(RuntimeException $e){if($e->getMessage()==='academy_data_busy')academy_json(['ok'=>false,'error'=>'busy'],409);throw $e;}
   try{
     $current=academy_read_node($path);
     if(!hash_equals(academy_data_hash($current),$expected)){
       // Never return possibly sensitive raw content in an error response.
       academy_release_data_locks($pdo,$locks);
       academy_json(['ok'=>false,'error'=>'conflict'],409);
     }
     $pdo->beginTransaction();
     try{academy_delete_node_raw($pdo,$path);academy_insert_value_raw($pdo,$path,$b['value']??null,$u['id']);$pdo->commit();}
     catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
   }finally{academy_release_data_locks($pdo,$locks);}
   academy_audit($u['id'],'data.transaction',$path);
   academy_json(['ok'=>true,'path'=>$path,'value'=>$b['value']??null]);
 }

 academy_json(['ok'=>false,'error'=>'not_found','route'=>$route],404);
}catch(Throwable$e){if($e->getMessage()==='academy_data_busy')academy_json(['ok'=>false,'error'=>'busy'],409);error_log('[academy-api] '.$e->getMessage());$env='production';try{$env=academy_config()['app']['environment']??'production';}catch(Throwable){}academy_json(['ok'=>false,'error'=>'server_error']+($env==='development'?['detail'=>$e->getMessage()]:[]),500);}
