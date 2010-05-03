"""
Module that exposes all the function to interact with a fastbit database, configured and interfaced with ntop.

"""
def query(partition, select_clause, where, limit):
    """
    Execute a fastbit query using ntop
    @type partition: string
    @param partition: required. indicates the from clause sql style (directory of the fastbit db partition  to query)
    @type select_clause: string
    @param select_clause: required. indicates the columns
    @type where: string
    @param where: required. indicates the where clause sql style
    @type limit: int 
    @param limit: required. indicates the max result fetched from the db

    @rtype: dictionary
    @return: a dictionary {'columns':[],'values':[]} containing all the values retrieved (max limit) or error otherwise 

    """
    pass
    