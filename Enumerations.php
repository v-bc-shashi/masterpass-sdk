<?php

/**
 *This enumeration defines the status values available for a submitted transaction.
 */
class TransactionStatus
{
    /**
     * Denotes that a transaction failed.
     */
    const Failure = "Failure";
    
    /**
     * Denotes that a transaction succeeded.
     */
    const Success = "Success";
}

class RealmType
{
    const eWallet = "eWallet";
    
    const meWallet = "meWallet";
}
