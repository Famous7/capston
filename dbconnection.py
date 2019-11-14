from os import environ
import pymysql
import logging


class Config:
    db_user = environ.get('DATABASE_USERNAME')
    db_password = environ.get('DATABASE_PASSWORD')
    db_host = environ.get('DATABASE_HOST')
    db_port = environ.get('DATABASE_PORT')
    db_name = environ.get('DATABASE_NAME')


class Database:
    def __init__(self, config):
        self.host = config.db_host
        self.username = config.db_user
        self.password = config.db_password
        self.port = config.db_port
        self.dbname = config.db_name
        self.conn = None

    def open_connection(self):
        try:
            if self.conn is None:
                self.conn = pymysql.connect(
                    host=self.host,
                    user=self.username,
                    passwd=self.password,
                    db=self.dbname,
                    connect_timeout=5
                )
        except pymysql.MySQLError as e:
            logging.error(e)
            raise e
        finally:
            logging.info('Connection opened')

    def exec_query(self, query, args=None):
        self.open_connection()
        try:
            with self.conn.cursor() as cur:
                if 'SELECT' in query:
                    cur.execute(query, args)
                    result = cur.fetchall()
                    return [row for row in result]
                else:
                    result = cur.execute(query, args)
                    self.conn.commit()
                    return f"{cur.rowcount} rows affected."
        except pymysql.MySQLError as e:
            print(e)
            if self.conn:
                self.conn.rollback()
        finally:
            if self.conn:
                self.conn.close()
                self.conn = None
                logging.info('Connection closed')


# if __name__ == '__main__':
#     config = Config()
#     db = Database(config)
#
#     print(db.exec_query('SELECT * from radio_info_tbl'))
#
#     db.exec_query('insert into radio_info_tbl(create_time, wi_fi, ble, num_of_visitors) values(now(), %s, %s, %s)', ('{"MAC": "11:11:11"}', '{"MAC": "11:11:11"}', 10))