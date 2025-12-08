import time
import logging

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase, CreateError
from django.core.exceptions import SuspiciousOperation

import boto3
from botocore.exceptions import ClientError


TABLE_NAME = getattr(
    settings, 'DYNAMODB_SESSIONS_TABLE_NAME', 'sessions')
HASH_ATTRIB_NAME = getattr(
    settings, 'DYNAMODB_SESSIONS_TABLE_HASH_ATTRIB_NAME', 'session_key')
ALWAYS_CONSISTENT = getattr(
    settings, 'DYNAMODB_SESSIONS_ALWAYS_CONSISTENT', True)

AWS_ACCESS_KEY_ID = getattr(
    settings, 'DYNAMODB_SESSIONS_AWS_ACCESS_KEY_ID', False)
if not AWS_ACCESS_KEY_ID:
    AWS_ACCESS_KEY_ID = getattr(
        settings, 'AWS_ACCESS_KEY_ID', None)

AWS_SECRET_ACCESS_KEY = getattr(
    settings, 'DYNAMODB_SESSIONS_AWS_SECRET_ACCESS_KEY', False)
if not AWS_SECRET_ACCESS_KEY:
    AWS_SECRET_ACCESS_KEY = getattr(settings, 'AWS_SECRET_ACCESS_KEY', None)

AWS_REGION_NAME = getattr(settings, 'DYNAMODB_SESSIONS_AWS_REGION_NAME', False)
if not AWS_REGION_NAME:
    AWS_REGION_NAME = getattr(settings, 'AWS_REGION_NAME', 'us-east-1')

# We'll find some better way to do this.
_DYNAMODB_CONN = None

logger = logging.getLogger(__name__)


def dynamodb_connection_factory():
    """
    Since SessionStore is called for every single page view, we'd be
    establishing new connections so frequently that performance would be
    hugely impacted. We'll lazy-load this here on a per-worker basis. Since
    boto3 resource objects are state-less (aside from security tokens),
    we're not too concerned about thread safety issues.
    """

    global _DYNAMODB_CONN
    if not _DYNAMODB_CONN:
        logger.debug("Creating a DynamoDB connection.")
        _DYNAMODB_CONN = boto3.resource(
            'dynamodb',
            region_name=AWS_REGION_NAME,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY
        )
    return _DYNAMODB_CONN


class SessionStore(SessionBase):
    """
    Implements DynamoDB session store.
    """

    def __init__(self, session_key=None):
        super(SessionStore, self).__init__(session_key)
        self.table = dynamodb_connection_factory().Table(TABLE_NAME)

    def load(self):
        """
        Loads session data from DynamoDB, runs it through the session
        data de-coder (base64->dict), sets ``self.session``.

        :rtype: dict
        :returns: The de-coded session data, as a dict.
        """

        try:
            response = self.table.get_item(
                Key={HASH_ATTRIB_NAME: self.session_key},
                ConsistentRead=ALWAYS_CONSISTENT
            )
            item = response.get('Item')
            if not item:
                self.create()
                return {}
        except (ClientError, SuspiciousOperation):
            self.create()
            return {}

        session_data = item.get('data', '')
        return self.decode(session_data)

    def exists(self, session_key):
        """
        Checks to see if a session currently exists in DynamoDB.

        :rtype: bool
        :returns: ``True`` if a session with the given key exists in the DB,
            ``False`` if not.
        """

        try:
            response = self.table.get_item(
                Key={HASH_ATTRIB_NAME: session_key},
                ConsistentRead=ALWAYS_CONSISTENT
            )
            return 'Item' in response
        except ClientError:
            return False

    def create(self):
        """
        Creates a new entry in DynamoDB. This may or may not actually
        have anything in it.
        """

        while True:
            try:
                # Save immediately to ensure we have a unique entry in the
                # database.
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            self._session_cache = {}
            return

    def save(self, must_create=False):
        """
        Saves the current session data to the database.

        :keyword bool must_create: If ``True``, a ``CreateError`` exception will
            be  raised if the saving operation doesn't create a *new* entry
            (as opposed to possibly updating an existing entry).
        :raises: ``CreateError`` if ``must_create`` is ``True`` and a session
            with the current session key already exists.
        """

        # If the save method is called with must_create equal to True, I'm
        # setting self._session_key equal to None and when
        # self.get_or_create_session_key is called the new
        # session_key will be created.
        if must_create:
            self._session_key = None

        self._get_or_create_session_key()
        
        session_data = self.encode(self._get_session(no_load=must_create))
        
        if must_create:
            # Create new session with condition that it doesn't exist
            try:
                self.table.put_item(
                    Item={
                        HASH_ATTRIB_NAME: self.session_key,
                        'data': session_data,
                        'created': int(time.time())
                    },
                    ConditionExpression='attribute_not_exists(#pk)',
                    ExpressionAttributeNames={'#pk': HASH_ATTRIB_NAME}
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    raise CreateError
                raise
        else:
            # Update existing session
            self.table.update_item(
                Key={HASH_ATTRIB_NAME: self.session_key},
                UpdateExpression='SET #data = :data',
                ExpressionAttributeNames={'#data': 'data'},
                ExpressionAttributeValues={':data': session_data}
            )

    def delete(self, session_key=None):
        """
        Deletes the current session, or the one specified in ``session_key``.

        :keyword str session_key: Optionally, override the session key
            to delete.
        """

        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key

        self.table.delete_item(
            Key={HASH_ATTRIB_NAME: session_key}
        )
