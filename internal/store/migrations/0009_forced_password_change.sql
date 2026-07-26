-- Force a password change on accounts whose password the operator did not choose.
--
-- The bootstrap admin's password is generated and printed to the startup log, so it
-- exists in scrollback, in journald, and in whatever ships those logs onward. The same
-- applies after an admin resets someone else's password: two people know it. Both are
-- fine as a way in and unacceptable as a way to stay in.
--
-- Existing installs default to false: their operators already chose those passwords, and
-- locking a running deployment out of its own console on upgrade would be a worse
-- failure than the one this prevents.
ALTER TABLE users
    ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
