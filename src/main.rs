use hex;
use sha3::{Digest, Sha3_256};
use base64::{engine::general_purpose, Engine as _};

fn sha3_256(input:String) -> String{
    let mut hasher = Sha3_256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    return hex::encode(result.to_owned());
}

fn string2u128(data:String, padding:bool) -> Vec<u128>{
    let mut data_u8_vec : Vec<u8> = data.into_bytes();
    if padding == true {
        if data_u8_vec.len()%16 != 0
        {
            let tmp = data_u8_vec.len()%16;
            for _i in tmp..16{
                data_u8_vec.push((16-tmp).try_into().unwrap());
            }
        }
        else
        {
            for _i in 0..16{
                data_u8_vec.push(16);
            }
        }
    }
    let mut data_vec : Vec<u128> = vec![];
    let tmp = data_u8_vec.len()/16;
    for j in 0..tmp{
        let i=j*16;
        data_vec.push(u128::from_be_bytes([data_u8_vec[i],data_u8_vec[i+1],data_u8_vec[i+2],data_u8_vec[i+3],data_u8_vec[i+4],data_u8_vec[i+5],data_u8_vec[i+6],data_u8_vec[i+7],data_u8_vec[i+8],data_u8_vec[i+9],data_u8_vec[i+10],data_u8_vec[i+11],data_u8_vec[i+12],data_u8_vec[i+13],data_u8_vec[i+14],data_u8_vec[i+15]]));
    }
    return data_vec;
}

fn u1282string(data:Vec<u128>) -> String{
    let mut u8_vec:Vec<u8> = vec![];
    let dl = data.len();
    for i in 0..dl {
        let tmp:[u8;16] = data[i].to_be_bytes();
        for j in 0..16{
            u8_vec.push(tmp[j]);
        }
    }
    let tmp = u8_vec[u8_vec.len()-1];
    for _i in 0..tmp{
        u8_vec.pop();
    }
    return String::from_utf8(u8_vec).expect("REASON");
}

fn base642u128(data:String) -> Vec<u128>{
    let data_u8_vec : Vec<u8> = general_purpose::STANDARD.decode(&data).expect("REASON");
    let mut data_vec : Vec<u128> = vec![];
    let tmp = data_u8_vec.len()/16;
    for j in 0..tmp{
        let i=j*16;
        data_vec.push(u128::from_be_bytes([data_u8_vec[i],data_u8_vec[i+1],data_u8_vec[i+2],data_u8_vec[i+3],data_u8_vec[i+4],data_u8_vec[i+5],data_u8_vec[i+6],data_u8_vec[i+7],data_u8_vec[i+8],data_u8_vec[i+9],data_u8_vec[i+10],data_u8_vec[i+11],data_u8_vec[i+12],data_u8_vec[i+13],data_u8_vec[i+14],data_u8_vec[i+15]]));
    }
    return data_vec;
}

fn u1282base64(data:Vec<u128>) -> String{
    let mut u8_vec:Vec<u8> = vec![];
    let dl = data.len();
    for i in 0..dl {
        let tmp:[u8;16] = data[i].to_be_bytes();
        for j in 0..16{
            u8_vec.push(tmp[j]);
        }
    }
    return general_purpose::STANDARD.encode(&u8_vec);
}

fn novu128pm(mut a:u128, mut b:u128) -> u128{
    let mut tmp:u8=0;
    let mut c:u128=0;
    let mut u128d2mp1:u128=1;
    u128d2mp1 += u128::MAX / 2;
    if a>=u128d2mp1 {
        a-=u128d2mp1;
        tmp+=1;
    }
    if b>=u128d2mp1 {
        b-=u128d2mp1;
        tmp+=1;
    }
    c=a+b;
    if tmp==2 || tmp==0 {
        return c;
    }
    if c>=u128d2mp1 {
        return c-u128d2mp1;
    }
    else {
        return c+u128d2mp1;
    }
}

fn novu128mm(a:u128, b:u128) -> u128{
    if a>=b {
        return a-b;
    }
    return u128::MAX-(b-a)+1;
}

fn rotate_r(data:u128, i:u128) -> u128{
    if i%128 == 0 {
        return data;
    }
    let mut tmp:u128 = 0;
    for j in 0..(i%128){
        tmp += 1<<j;
    }
    return (data>>(i%128)) + (((data&tmp)<<(128-(i%128))));
}

fn rotate_l(data:u128, i:u128) -> u128{
    if i%128 == 0 {
        return data;
    }
    let mut tmp:u128 = 0;
    for j in 0..(128-(i%128)){
        tmp += 1<<j;
    }
    return (data>>(128-(i%128))) + (((data&tmp)<<(i%128)));
}

fn encrypt(data:String, key:String) -> String{
    // key start
    let mut key_vec = Vec::new();
    key_vec.push(sha3_256(key));
    for i in 0..31{
        key_vec.push(sha3_256(key_vec[i].clone()));
    }
    // key end
    // data start
    let mut data_vec = string2u128(data,true);
    // data end
    // encrypt start
    for round in 0..32{
        let keys = string2u128(key_vec[round].clone(), false);
        let dvl = data_vec.len()-1;

        for i in 0..dvl{
            data_vec[i]=novu128pm(data_vec[i], data_vec[i+1].clone());
        }
        data_vec[dvl] = novu128pm(data_vec[dvl],keys[0].clone());

        for i in 0..=dvl{
            data_vec[i]=data_vec[i]^keys[1].clone();
        }

        for i in 0..=dvl{
            data_vec[i] = rotate_r(data_vec[i], i.clone() as u128);
        }

        let mut ii=dvl;
        while ii>0{
            data_vec[ii]=novu128pm(data_vec[ii], data_vec[ii-1].clone());
            ii-=1;
        }
        data_vec[0] = novu128pm(data_vec[0],keys[0].clone());

        for i in 0..=dvl{
            data_vec[i] = !data_vec[i];
        }
    }
    // encrypt end
    return u1282base64(data_vec);
}

fn decrypt(data:String, key:String) -> String{
    // key start
    let mut key_vec = Vec::new();
    key_vec.push(sha3_256(key));
    for i in 0..31{
        key_vec.push(sha3_256(key_vec[i].clone()));
    }
    // key end
    // data start
    let mut data_vec = base642u128(data);
    // data end
    // decrypt start
    let mut round = 32;
    while round > 0 {
        round-=1;
        let keys = string2u128(key_vec[round].clone(), false);
        let dvl = data_vec.len()-1;

        for i in 0..=dvl{
            data_vec[i] = !data_vec[i];
        }

        data_vec[0] = novu128mm(data_vec[0],keys[0].clone());
        for i in 1..=dvl{
            data_vec[i]=novu128mm(data_vec[i], data_vec[i-1].clone());
        }

        for i in 0..=dvl{
            data_vec[i] = rotate_l(data_vec[i], i.clone() as u128);
        }

        for i in 0..=dvl{
            data_vec[i]=data_vec[i]^keys[1].clone();
        }

        data_vec[dvl] = novu128mm(data_vec[dvl],keys[0].clone());
        let mut i=dvl;
        while i>0{
            i-=1;
            data_vec[i]=novu128mm(data_vec[i], data_vec[i+1].clone());
        }
    }
    // decrypt end
    return u1282string(data_vec);
}

fn main(){
    let text = "Hello, world!!".to_string();
    let key = "ItIsKey".to_string();
    let encrypted = encrypt(text.clone(), key.clone());
    let decrypted = decrypt(encrypted.clone(), key.clone());
    println!("{} {} {}", text.clone(), encrypted, decrypted);
}
