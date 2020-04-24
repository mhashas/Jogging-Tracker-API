import re

class QueryFilterParser:

    OR = ' OR '
    AND = ' AND '
    NOT_EQUALS = ' ne '
    EQUALS = ' eq '
    GREATER_THAN = ' gt '
    LOWER_THAN = ' lt '

    def parse_query_filter(self, query):
        query = query.replace(self.AND, '&').replace(self.OR, '|')
        query = query.replace('(', 'Q(').replace('Q(Q(', 'Q(').replace('))', ')')
        query = query.replace(self.EQUALS, '__exact=')
        query = query.replace(self.LOWER_THAN, '__lt=')
        query = query.replace(self.GREATER_THAN, '__gt=')

        ne_position = query.find(' ne ')
        while ne_position != -1:
            query = query.replace(' ne ', '__exact=', 1)
            q_ne_position = query.rfind('Q', 0, ne_position)
            query = query[:q_ne_position] + '~Q' + query[q_ne_position + 1:]

            ne_position = query.find(' ne ')

        return query

if __name__ == '__main__':
    str = QueryFilterParser().parse_query_filter("(date eq '2016-05-01') AND ((time eq 30) AND (time ne 60)) AND ((distance gt 20) OR (distance lt 10)) AND (location ne Amsterdam)")
    print(str)
