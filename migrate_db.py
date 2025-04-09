import sqlite3

def main():
    print("开始数据库迁移...")
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    try:
        # 检查当前表结构
        c.execute("PRAGMA table_info(messages)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'message_type' in columns:
            print("数据库已是最新版本，无需迁移")
            return
        
        # 执行迁移
        print("1. 重命名旧表...")
        c.execute("ALTER TABLE messages RENAME TO messages_old")
        
        print("2. 创建新表结构...")
        c.execute('''CREATE TABLE messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT,
                     is_private INTEGER DEFAULT 0,
                     target_user TEXT DEFAULT NULL,
                     message_type TEXT DEFAULT 'text')''')
        
        print("3. 迁移数据...")
        c.execute('''INSERT INTO messages 
                    (id, username, message, timestamp, color, is_private, target_user, message_type)
                    SELECT id, username, message, timestamp, color, is_private, target_user, 
                           CASE WHEN message LIKE '[图片]%' THEN 'image' ELSE 'text' END
                    FROM messages_old''')
        
        print("4. 清理旧表...")
        c.execute("DROP TABLE messages_old")
        
        print("5. 创建索引...")
        c.execute("CREATE INDEX idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX idx_messages_private ON messages(is_private, target_user)")
        c.execute("CREATE INDEX idx_messages_type ON messages(message_type)")
        
        conn.commit()
        print("数据库迁移成功完成！")
        
    except Exception as e:
        conn.rollback()
        print(f"迁移失败: {str(e)}")
        raise
    finally:
        conn.close()

if __name__ == '__main__':
    main()
