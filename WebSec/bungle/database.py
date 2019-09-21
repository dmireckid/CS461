import MySQLdb as mdb
from bottle import FormsDict
from hashlib import md5

# connection to database project2
def connect():
    """makes a connection to MySQL database.
    @return a mysqldb connection
    """

    #TODO: fill out function parameters. Use the user/password combo for the user you created in 2.1.2.1

    return mdb.connect(host="localhost",
                       user="mirecki2",
                       passwd="a19e87d10737bc2e10f62a9f8857fdb6da8f37ebb8f28cc5c1a2bf2aedb927bf",
                       db="project2");

def createUser(username, password):
    """ creates a row in table named users
    @param username: username of user
    @param password: password of user
    """

    db_rw = connect()
    cur = db_rw.cursor()

    #TODO: Implement a prepared statement using cur.execute() so that this query creates a row in table user
    insert_stmt = (
    "INSERT INTO users(username,password,passwordhash) "
    "VALUES(%s,%s,%s)"
    )
    insert_data = (username, password, md5)
    cur.execute(insert_stmt, insert_data)

    db_rw.commit()

def validateUser(username, password):
    """ validates if username,password pair provided by user is correct or not
    @param username: username of user
    @param password: password of user
    @return True if validation was successful, False otherwise.
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO: Implement a prepared statement using cur.execute() so that this query selects a row from table user
    insert_stmt = (
    "SELECT username, password "
    "FROM users "
    "WHERE username=%s AND password=%s"
    )
    insert_data = (username, password)
    cur.execute(insert_stmt, insert_data)

    if cur.rowcount < 1:
        return False
    return True

def fetchUser(username):
    """ checks if there exists given username in table users or not
    if user exists return (id, username) pair
    if user does not exist return None
    @param username: the username of a user
    @return The row which has username is equal to provided input
    """

    db_rw = connect()
    cur = db_rw.cursor(mdb.cursors.DictCursor)
    print username
    #TODO: Implement a prepared statement so that this query selects a id and username of the row which has column username = username
    insert_stmt = (
    "SELECT id, username "
    "FROM users "
    "WHERE username=%s"
    )
    insert_data = (username,)
    cur.execute(insert_stmt, insert_data)

    if cur.rowcount < 1:
        return None
    return FormsDict(cur.fetchone())

def addHistory(user_id, query):
    """ adds a query from user with id=user_id into table named history
    @param user_id: integer id of user
    @param query: the query user has given as input
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO: Implement a prepared statment using cur.execute() so that this query inserts a row in table history
    insert_stmt = (
    "INSERT INTO history(user_id,query) "
    "VALUES(%s,%s)"
    )
    insert_data = (user_id, query)
    cur.execute(insert_stmt, insert_data)

    db_rw.commit()

def getHistory(user_id):
    """ grabs last 15 queries made by user with id=user_id from
    table named history in descending order of when the searches were made
    @param user_id: integer id of user
    @return a first column of a row which MUST be query
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO: Implement a prepared statement using cur.execute() so that this query selects 15 queries from table history in descending order of when the searches were made
    insert_stmt = (
    "SELECT query "
    "FROM history "
    "WHERE user_id=%s "
    "ORDER BY id DESC "
    "LIMIT 15"
    )
    insert_data = (user_id,)
    cur.execute(insert_stmt, insert_data)

    rows = cur.fetchall();
    return [row[0] for row in rows]
