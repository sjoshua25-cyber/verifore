const express=require('express'),session=require('express-session'),bcrypt=require('bcryptjs'),
multer=require('multer'),Database=require('better-sqlite3'),path=require('path'),fs=require('fs'),crypto=require('crypto');
const ROOT=process.env.DATA_DIR||path.join(__dirname,'data'),UP=path.join(ROOT,'uploads');
fs.mkdirSync(path.join(ROOT,'database'),{recursive:true});fs.mkdirSync(UP,{recursive:true});
const db=new Database(path.join(ROOT,'database','forensic.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,email TEXT,full_name TEXT,mobile TEXT,institution TEXT,user_type TEXT,id_number TEXT,role TEXT,hash TEXT);
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,case_id TEXT UNIQUE,user_id INT,status TEXT DEFAULT 'Draft',priority TEXT DEFAULT 'Normal',is_sample INT DEFAULT 0,
 info TEXT DEFAULT '{}',scene TEXT DEFAULT '{}',stains TEXT DEFAULT '[]',patterns TEXT DEFAULT '[]',analysis TEXT DEFAULT '{}',created TEXT,updated TEXT);
CREATE TABLE IF NOT EXISTS evidence_images(id INTEGER PRIMARY KEY,case_id TEXT,category TEXT,original_name TEXT,stored_name TEXT,size INT,width INT,height INT,uploaded TEXT);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY,actor TEXT,action TEXT,case_id TEXT,at TEXT,description TEXT);`);
const now=()=>new Date().toISOString(),J=JSON.stringify;
const log=(actor,action,case_id,d='')=>db.prepare('INSERT INTO audit_logs(actor,action,case_id,at,description)VALUES(?,?,?,?,?)').run(actor,action,case_id||null,now(),d);
const mkUser=(u,p,role,name)=>{if(!db.prepare('SELECT 1 FROM users WHERE username=?').get(u))db.prepare('INSERT INTO users(username,email,full_name,institution,user_type,role,hash)VALUES(?,?,?,?,?,?,?)').run(u,u+'@example.org',name,'Demo Institution','Investigator',role,bcrypt.hashSync(p,10))};
mkUser('demo_user','Demo@123','user','Demo User (DEVELOPMENT)');mkUser('admin','Admin@123','admin','Forensic Analyst (DEVELOPMENT)');
const nextId=()=>{const y=new Date().getFullYear(),n=db.prepare('SELECT COUNT(*)c FROM cases').get().c+1;return `BPA-${y}-${String(n).padStart(4,'0')}`};
if(!db.prepare('SELECT 1 FROM cases').get()){const u=db.prepare("SELECT id FROM users WHERE username='demo_user'").get().id;
 ['Passive','Transfer','Cast-Off','Projected','Drip Trail'].forEach(p=>{const id=nextId();
 db.prepare('INSERT INTO cases(case_id,user_id,status,is_sample,info,patterns,stains,created,updated)VALUES(?,?,?,?,?,?,?,?,?)').run(id,u,'Submitted',1,
 J({incidentRef:'SAMPLE-'+p,location:'SAMPLE / DEMO DATA ONLY',evidenceDescription:'Demonstration case'}),J([p]),J([{id:'S1',length:10,width:5,unit:'mm',shape:'Elliptical',feature:'Parent Stain'}]),now(),now())})}
const app=express();app.use(express.json({limit:'2mb'}));
app.use(session({secret:process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'strict',maxAge:30*60*1000},rolling:true}));
const auth=(req,res,next)=>req.session.user?next():res.status(401).json({error:'Authentication required.'});
const adminOnly=(req,res,next)=>req.session.user.role==='admin'?next():res.status(403).json({error:'Administrator access required.'});
const getCase=(req,res)=>{const c=db.prepare('SELECT * FROM cases WHERE case_id=?').get(req.params.id);
 if(!c||(req.session.user.role!=='admin'&&c.user_id!==req.session.user.id)){res.status(404).json({error:'Case not found.'});return null}return c};
const parse=c=>({...c,info:JSON.parse(c.info),scene:JSON.parse(c.scene),stains:JSON.parse(c.stains),patterns:JSON.parse(c.patterns),analysis:JSON.parse(c.analysis)});
app.post('/api/register',(req,res)=>{const b=req.body;
 if(!b.username||!b.full_name||!/^\S+@\S+\.\S+$/.test(b.email||''))return res.status(400).json({error:'Full name, username, and a valid email are required.'});
 if(!b.password||b.password.length<6)return res.status(400).json({error:'Password must be at least 6 characters long.'});
 if(db.prepare('SELECT 1 FROM users WHERE username=?').get(b.username))return res.status(409).json({error:'Username is already taken. Please choose another.'});
 if(db.prepare('SELECT 1 FROM users WHERE email=?').get(b.email))return res.status(409).json({error:'An account with this email already exists.'});
 const targetRole=b.role==='admin'?'admin':'user';
 const targetType=targetRole==='admin'?(b.user_type||'Forensic Analyst'):(b.user_type||'Investigator');
 db.prepare('INSERT INTO users(username,email,full_name,mobile,institution,user_type,id_number,role,hash)VALUES(?,?,?,?,?,?,?,?,?)')
   .run(b.username,b.email,b.full_name,b.mobile||'',b.institution||'Forensic Agency',targetType,b.id_number||'',targetRole,bcrypt.hashSync(b.password,10));
 log(b.username,`Account created (${targetRole})`);res.json({ok:true,role:targetRole})});
app.post('/api/login',(req,res)=>{const{username,password,role}=req.body;
 const u=db.prepare('SELECT * FROM users WHERE (username=? OR email=?) AND role=?').get(username,username,role);
 if(!u||!bcrypt.compareSync(password||'',u.hash))return res.status(401).json({error:'Invalid credentials for the selected role.'});
 req.session.regenerate(()=>{req.session.user={id:u.id,username:u.username,role:u.role,name:u.full_name};log(u.username,'Login');res.json(req.session.user)})});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',auth,(req,res)=>res.json(req.session.user));
app.get('/api/cases',auth,(req,res)=>{const a=req.session.user.role==='admin';
 const r=a?db.prepare('SELECT c.*,u.full_name submitter FROM cases c JOIN users u ON u.id=c.user_id ORDER BY updated DESC').all()
 :db.prepare('SELECT c.*,? submitter FROM cases c WHERE user_id=? ORDER BY updated DESC').all(req.session.user.name,req.session.user.id);res.json(r.map(parse))});
app.post('/api/cases',auth,(req,res)=>{const id=nextId();
 db.prepare('INSERT INTO cases(case_id,user_id,info,scene,stains,patterns,created,updated)VALUES(?,?,?,?,?,?,?,?)').run(id,req.session.user.id,J(req.body.info||{}),J(req.body.scene||{}),J(req.body.stains||[]),J(req.body.patterns||[]),now(),now());
 log(req.session.user.username,'Case created',id);res.json({case_id:id})});
app.get('/api/cases/:id',auth,(req,res)=>{const c=getCase(req,res);if(!c)return;
 const imgs=db.prepare('SELECT id,category,original_name,size,width,height,uploaded FROM evidence_images WHERE case_id=?').all(c.case_id);
 if(req.session.user.role==='admin')log(req.session.user.username,'Case opened by analyst',c.case_id);res.json({...parse(c),images:imgs})});
app.put('/api/cases/:id',auth,(req,res)=>{const c=getCase(req,res);if(!c)return;const b=req.body,adm=req.session.user.role==='admin';
 if(!adm){if(c.status!=='Draft'&&c.status!=='Additional Information Required')return res.status(403).json({error:'Submitted cases cannot be edited.'});
  db.prepare('UPDATE cases SET info=?,scene=?,stains=?,patterns=?,updated=? WHERE case_id=?').run(J(b.info),J(b.scene),J(b.stains),J(b.patterns),now(),c.case_id)}
 else{const S=['Draft','Submitted','Under Review','Analysis in Progress','Additional Information Required','Analysis Completed','Report Generated','Archived'];
  if(b.status&&!S.includes(b.status))return res.status(400).json({error:'Invalid status.'});
  db.prepare('UPDATE cases SET analysis=?,patterns=COALESCE(?,patterns),status=COALESCE(?,status),priority=COALESCE(?,priority),updated=? WHERE case_id=?').run(J(b.analysis||{}),b.patterns?J(b.patterns):null,b.status||null,b.priority||null,now(),c.case_id);
  if(b.status&&b.status!==c.status)log(req.session.user.username,'Status changed',c.case_id,c.status+' → '+b.status)}
 log(req.session.user.username,adm?'Analysis updated':'Case updated',c.case_id);res.json({ok:true})});
app.post('/api/cases/:id/submit',auth,(req,res)=>{const c=getCase(req,res);if(!c)return;
 if(!db.prepare('SELECT 1 FROM evidence_images WHERE case_id=?').get(c.case_id))return res.status(400).json({error:'Upload at least one photograph before submitting.'});
 db.prepare("UPDATE cases SET status='Submitted',updated=? WHERE case_id=?").run(now(),c.case_id);log(req.session.user.username,'Case submitted',c.case_id);res.json({ok:true})});
const CATS=['Overall Scene','Mid-Range','Close-Up','Scale Photograph','Bloodstain Pattern','Individual Stain','Surface','Other Evidence'];
const ok={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'};
const up=multer({storage:multer.memoryStorage(),limits:{fileSize:15*1024*1024,files:20},fileFilter:(r,f,cb)=>cb(null,!!ok[f.mimetype])});
app.post('/api/cases/:id/images',auth,up.array('images',20),(req,res)=>{const c=getCase(req,res);if(!c)return;
 if(c.status!=='Draft'&&c.status!=='Additional Information Required'&&req.session.user.role!=='admin')return res.status(403).json({error:'Case is locked.'});
 const cat=CATS.includes(req.body.category)?req.body.category:'Other Evidence';
 if(!req.files||!req.files.length)return res.status(400).json({error:'Invalid upload: only JPG, PNG or WebP up to 15 MB.'});
 const dir=path.join(UP,c.case_id,cat.toLowerCase().replace(/\W+/g,'-'));fs.mkdirSync(dir,{recursive:true});
 const dims=[].concat(req.body.dims||[]);
 req.files.forEach((f,i)=>{const n=crypto.randomUUID()+ok[f.mimetype];fs.writeFileSync(path.join(dir,n),f.buffer);
  const[w,h]=(dims[i]||'0x0').split('x').map(Number);
  db.prepare('INSERT INTO evidence_images(case_id,category,original_name,stored_name,size,width,height,uploaded)VALUES(?,?,?,?,?,?,?,?)').run(c.case_id,cat,path.basename(f.originalname),path.join(path.basename(dir),n),f.size,w||0,h||0,now());
  log(req.session.user.username,'Image uploaded',c.case_id,f.originalname)});res.json({ok:true})});
app.get('/api/images/:imgId',auth,(req,res)=>{const i=db.prepare('SELECT * FROM evidence_images WHERE id=?').get(+req.params.imgId);if(!i)return res.sendStatus(404);
 const c=db.prepare('SELECT user_id FROM cases WHERE case_id=?').get(i.case_id);
 if(req.session.user.role!=='admin'&&c.user_id!==req.session.user.id)return res.sendStatus(404);
 const f=path.resolve(UP,i.case_id,i.stored_name);if(!f.startsWith(path.resolve(UP)+path.sep))return res.sendStatus(400);res.sendFile(f)});
app.get('/api/audit',auth,adminOnly,(req,res)=>res.json(db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500').all()));
const publicDir=fs.existsSync(path.join(__dirname,'..','public'))?path.join(__dirname,'..','public'):fs.existsSync(path.join(__dirname,'public'))?path.join(__dirname,'public'):__dirname;
app.use(express.static(publicDir));
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`VERIFORE Forensic System running on http://localhost:${PORT}`));
