.. _porting:

Porting to OS
#############

The Remote Procedure Serialization needs port to your operating system or bare-metal application.
You have to provide:

	* Os specific function depends on ``include/rp_os.h``
	* rp_log.h for logging system abstraction depends on template ``template/rp_log.h``
	* One or more transport layer depends on template ``template/rp_trans_tmpl.h``


Os porting Zephyr
=================

Creating instance:
------------------

When creating a new Remote Procedure Serialization instance the locking mechanism data type have to be indicated:

.. code-block:: c

	RP_SER_DEFINE(entropy_ser, struct k_sem, 0, 1000, 0);

Example rp_os.c source file:

.. code-block:: c

	rp_err_t rp_os_signal_init(struct rp_ser *rp)
	{
		int err;
		struct k_sem *sem = RP_OS_SIGNAL_GET(struct k_sem, rp);

		err = k_sem_init(sem, 0, 1);
		if (err) {
			return RP_ERROR_OS_ERROR;
		}

		return RP_SUCCESS;
	}

	rp_err_t rp_os_response_wait(struct rp_ser *rp)
	{
		int err;
		struct k_sem *sem = RP_OS_SIGNAL_GET(struct k_sem, rp);

		err = k_sem_take(sem, CONFIG_RP_OS_RSP_WAIT_TIME);
		if (err) {
			return RP_ERROR_OS_ERROR;
		}

		return RP_SUCCESS;
	}

	rp_err_t rp_os_response_signal(struct rp_ser *rp)
	{
		struct k_sem *sem = RP_OS_SIGNAL_GET(struct k_sem, rp);

		k_sem_give(sem);

		return RP_SUCCESS;
	}
