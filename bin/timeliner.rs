use std::collections::BTreeMap;

use chrono::{Utc, TimeZone};
use serde::{Deserialize, Serialize};
use shellbags::{read_all_shell_bags, shellbag::ShellBagPath};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShellBagTimeline<'a> {
    pub action : ShellBagAction,
    pub time : String,
    pub numeric_time : i64,
    pub folder : String,
    pub user : &'a str
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ShellBagAction {
    Modified,
    Access,
    Created
}

pub fn main() {
    unsafe {
        let empty_path = String::new();
        match read_all_shell_bags() {
            Ok(list) => {
                let mut timeline : BTreeMap<i64, Vec<ShellBagTimeline>> = BTreeMap::new();
                
                for (user, bags) in &list {
                    let mut path_association : BTreeMap<&ShellBagPath, String> = BTreeMap::new();
                    for (path, bag) in &bags.ntuser.list {
                        let parent_path = if path.0.len() > 0 {
                            let mut pth = path.0.clone();
                            pth.pop();
                            ShellBagPath(pth)
                        }else {
                            ShellBagPath(Vec::new())
                        };
                        let parent_path = match path_association.get(&parent_path) {
                            Some(path_name) => path_name,
                            None => &empty_path
                        };
                        match &bag.1 {
                            shellbags::shellbag::ShellItem::Folder(v) => {
                                path_association.insert(path, format!("{}\\{}",parent_path,v.name));
                            },
                            shellbags::shellbag::ShellItem::Volume(v) => {
                                path_association.insert(path, format!("{}\\{}",parent_path,v.name));
                            },
                            shellbags::shellbag::ShellItem::File(v) => {
                                path_association.insert(path, format!("{}\\{}",parent_path,v.long_name));
                            },
                            shellbags::shellbag::ShellItem::Network(v) =>{
                                path_association.insert(path, format!("{}\\{}",parent_path,v.location));
                            },
                            shellbags::shellbag::ShellItem::Unknown(_) => {
                                path_association.insert(path, format!("{}\\?",parent_path));
                            },
                        }
                    }
                    for (path, bag) in &bags.ntuser.list {
                        let parent_path = match path_association.get(path) {
                            Some(path_name) => path_name,
                            None => &empty_path
                        };
                        match &bag.1 {
                            shellbags::shellbag::ShellItem::File(v) => {
                                let mut time_vec = match timeline.remove(&v.a_time) {
                                    Some(v) => v,
                                    None => Vec::with_capacity(4)
                                };
                                let time = Utc.timestamp(v.a_time, 0 ).to_string();
                                time_vec.push(ShellBagTimeline { action: ShellBagAction::Access, numeric_time : v.a_time, folder: parent_path.clone(), user: &user[..], time});
                                timeline.insert(v.a_time, time_vec);

                                let mut time_vec = match timeline.remove(&v.m_time) {
                                    Some(v) => v,
                                    None => Vec::with_capacity(4)
                                };
                                let time = Utc.timestamp(v.m_time, 0).to_string();
                                time_vec.push(ShellBagTimeline { action: ShellBagAction::Modified, numeric_time : v.m_time, folder: parent_path.clone(), user: &user[..], time });
                                timeline.insert(v.m_time, time_vec);

                                let mut time_vec = match timeline.remove(&v.c_time) {
                                    Some(v) => v,
                                    None => Vec::with_capacity(4)
                                };
                                let time = Utc.timestamp(v.c_time,0 ).to_string();
                                time_vec.push(ShellBagTimeline { action: ShellBagAction::Created, numeric_time : v.c_time, folder: parent_path.clone(), user: &user[..], time });
                                timeline.insert(v.c_time, time_vec);
                            },
                            _ => {}
                        }
                    }
                    for (user, bags) in &list {
                        let mut path_association : BTreeMap<&ShellBagPath, String> = BTreeMap::new();
                        for (path, bag) in &bags.usr_class.list {
                            let parent_path = if path.0.len() > 0 {
                                let mut pth = path.0.clone();
                                pth.pop();
                                ShellBagPath(pth)
                            }else {
                                ShellBagPath(Vec::new())
                            };
                            let parent_path = match path_association.get(&parent_path) {
                                Some(path_name) => path_name,
                                None => &empty_path
                            };
                            match &bag.1 {
                                shellbags::shellbag::ShellItem::Folder(v) => {
                                    path_association.insert(path, format!("{}\\{}",parent_path,v.name));
                                },
                                shellbags::shellbag::ShellItem::Volume(v) => {
                                    path_association.insert(path, format!("{}\\{}",parent_path,v.name));
                                },
                                shellbags::shellbag::ShellItem::File(v) => {
                                    path_association.insert(path, format!("{}\\{}",parent_path,v.long_name));
                                },
                                shellbags::shellbag::ShellItem::Network(v) =>{
                                    path_association.insert(path, format!("{}\\{}",parent_path,v.location));
                                },
                                shellbags::shellbag::ShellItem::Unknown(_) => {
                                    path_association.insert(path, format!("{}\\?",parent_path));
                                },
                            }
                        }
                        for (path, bag) in &bags.usr_class.list {
                            let parent_path = match path_association.get(path) {
                                Some(path_name) => path_name,
                                None => &empty_path
                            };
                            match &bag.1 {
                                shellbags::shellbag::ShellItem::File(v) => {
                                    let mut time_vec = match timeline.remove(&v.a_time) {
                                        Some(v) => v,
                                        None => Vec::with_capacity(4)
                                    };
                                    let time = Utc.timestamp(v.a_time, 0).to_string();
                                    time_vec.push(ShellBagTimeline { action: ShellBagAction::Access, numeric_time : v.a_time, folder: parent_path.clone(), user: &user[..], time});
                                    timeline.insert(v.a_time, time_vec);
    
                                    let mut time_vec = match timeline.remove(&v.m_time) {
                                        Some(v) => v,
                                        None => Vec::with_capacity(4)
                                    };
                                    let time = Utc.timestamp(v.m_time, 0).to_string();
                                    time_vec.push(ShellBagTimeline { action: ShellBagAction::Modified, numeric_time : v.m_time, folder: parent_path.clone(), user: &user[..], time });
                                    timeline.insert(v.m_time, time_vec);
    
                                    let mut time_vec = match timeline.remove(&v.c_time) {
                                        Some(v) => v,
                                        None => Vec::with_capacity(4)
                                    };
                                    let time = Utc.timestamp(v.c_time, 0).to_string();
                                    time_vec.push(ShellBagTimeline { action: ShellBagAction::Created, numeric_time : v.c_time, folder: parent_path.clone(), user: &user[..], time });
                                    timeline.insert(v.c_time, time_vec);
                                },
                                _ => {}
                            }
                        }
                    }
                }
                let mut timeline_vec : Vec<ShellBagTimeline> = Vec::with_capacity(4096);
                for (_time, events) in timeline {
                    for event in events {
                        timeline_vec.push(event);
                    }
                }
                println!("{}", serde_json::to_string_pretty(&timeline_vec).unwrap());
            },
            Err(e) => {
                println!("ERROR: {:?}",e);
            }
        }
    }
}